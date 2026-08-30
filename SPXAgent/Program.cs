namespace SpxAgent;

// SPX agent skeleton entry point.
//
// Usage:
//   spx-agent <host> <port>
//
// The agent generates a fresh Ed25519 keypair on each run and prints the hex
// public key, which must be added to the server's server.yaml:
//
//   spx:
//     - host: "0.0.0.0"
//       port: 9999
//       authorized_keys:
//         - "<hex public key from agent output>"
//
// Server certificate pinning is NOT yet wired (SpxClient.ValidateServerCertificate
// accepts anything) - see the TODO there.
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        string host = args.Length > 0 ? args[0] : "127.0.0.1";
        int port = args.Length > 1 ? int.Parse(args[1]) : 9999;

        var identity = new AgentIdentity();
        Console.WriteLine($"[*] agent public key (hex): {identity.PublicKeyHex}");
        Console.WriteLine($"[*] connecting to {host}:{port} ...");

        using var client = await SpxClient.ConnectAsync(host, port, identity);
        await client.AuthenticateAsync();
        Console.WriteLine("[+] AUTH OK");

        string sessionId = await client.RegisterAsync();
        Console.WriteLine($"[+] registered session: {sessionId}");

        using var cts = new CancellationTokenSource();

        // Heartbeat loop + command read loop.
        var pingTask = HeartbeatAsync(client, cts.Token);
        var runTask = client.RunAsync(cts.Token);
        await Task.WhenAny(pingTask, runTask);

        cts.Cancel();
        return 0;
    }

    private static async Task HeartbeatAsync(SpxClient client, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                bool pong = await client.PingAsync(ct);
                Console.WriteLine($"[+] ping -> pong: {pong}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ping failed: {ex.Message}");
                return;
            }
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
        }
    }
}
