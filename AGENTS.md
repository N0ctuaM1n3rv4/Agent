# Repository Guidelines

## Project Overview

`SPXAgent` is a minimal .NET 8 C# console agent that implements the **SPX wire protocol** — a Sliver-server C2 framing format. It connects to a server over TLS 1.2/1.3, authenticates with an Ed25519 challenge-response, registers a session, then loops on heartbeat PING while reading server frames. Command execution is a stub (`CMD` frames are only logged). The project is a skeleton (agent version `"0.1-skeleton"`): no tests, no CI, no logging library.

## Architecture & Data Flow

Startup flow (`Program.cs` → `Main`):

```
args (host, port; defaults 127.0.0.1:9999)
  → new AgentIdentity()               # Ed25519 keypair (fresh or SPX_AGENT_KEY seed)
  → print hex pubkey                  # must be added to server.yaml spx.authorized_keys
  → SpxClient.ConnectAsync            # TCP → SslStream (TLS 1.2/1.3)
  → AuthenticateAsync                 # AUTH: sign base64 nonce → reply M={pubkey,sig} → AUTH_OK
  → RegisterAsync                     # REG (c=0x0001, f=0x01 session mode, host metadata) → REG_OK → SessionId
  → Task.WhenAny(HeartbeatAsync, RunAsync) → cts.Cancel() → return 0
```

- `HeartbeatAsync` sends PING every 30 s and expects PONG; any error stops the heartbeat (and thereby the whole agent, via `WhenAny`).
- `RunAsync` is the read loop, dispatching every frame to `HandleServerFrameAsync` (switch on `T`: `CMD`/`DATA`/`CLOSE`/`ERR`, all logged only).
- `PingAsync` itself loops reading frames until a PONG matching its request id; stray frames are passed to `HandleServerFrameAsync` (no data loss).

**Wire framing** (`Frame.cs`): 14-byte big-endian head (`[0:4]` magic `"S1XT"` = `0x53315854`, `[4]` version `0x01`, `[5]` flags, `[6:10]` headerLen u32, `[10:14]` payloadLen u32) + JSON header + raw payload. Message types: `AUTH|AUTH_OK|REG|REG_OK|CMD|RES|TASK|TASK_RES|PING|PONG|OPEN|DATA|CLOSE|ERR`. Header JSON field names are single-letter via `[JsonPropertyName]` attributes (mirroring Go `server/c2/spx.go`).

**Module graph**: `Program` → `AgentIdentity` (crypto) and → `SpxClient` (lifecycle); `SpxClient` → `Frame`/`SpxHeader` (protocol) and → `AgentIdentity` (sign/pubkey). `Frame` is standalone (no internal deps).

## Key Directories

Single project — all source under `SPXAgent/`. No `tests/`, `scripts/`, or `docs/` directories exist.

| Path | Purpose |
|---|---|
| `SPXAgent/Program.cs` | Entry point; startup sequence + heartbeat orchestration |
| `SPXAgent/AgentIdentity.cs` | Ed25519 identity (`_key`), pubkey export, signer |
| `SPXAgent/Frame.cs` | Binary framing + `SpxHeader` JSON model + size caps |
| `SPXAgent/SpxClient.cs` | TLS transport + AUTH/REG/PING/frame-dispatch lifecycle |
| `SPXAgent/SPXAgent.csproj` | Project file (net8.0, NSec.Cryptography 25.4.0) |
| `agents.sln` | Solution (single project, Debug/Release Any CPU) |

`bin/` and `obj/` are build artifacts (gitignored).

## Development Commands

- **Build**: `dotnet build agents.sln`
- **Run**: `dotnet run --project SPXAgent` (artifact: `SPXAgent/bin/Debug/net8.0/spx-agent.exe`); CLI args `host port`
- **Package manager**: NuGet (restore happens via `dotnet build`/`dotnet run`)
- **No lint/test commands exist.** No formatter config, no `Directory.Build.props`, no `global.json`, no `nuget.config`.

## Code Conventions & Common Patterns

- **Target framework**: `net8.0`, SDK-style (`Microsoft.NET.Sdk`), `OutputType=Exe`, `AssemblyName=spx-agent`, `RootNamespace=SpxAgent`. **`<Nullable>enable</Nullable>` and `<ImplicitUsings>enable</ImplicitUsings>`** — match both in new files.
- **Naming**: PascalCase for public members/types; `_camelCase` for private readonly fields (`_key`, `_host`, `_port`, `_identity`, `_tcp`, `_ssl`). No records so far; one mutable POCO (`SpxHeader`) and one tuple return `(SpxHeader Header, byte[] Payload)`.
- **Async**: fully `async`/`await`; `CancellationToken` threaded through loops (`PingAsync`/`RunAsync`/`HeartbeatAsync`). Stream I/O uses `await WriteAsync`/`ReadAsync` with a custom partial-read loop (`Frame.ReadExactAsync`) — reuse it; never assume a single `ReadAsync` fills the buffer.
- **Error handling**: exceptions only, no Result types — `InvalidDataException` (protocol/auth failures), `InvalidOperationException` (oversized frames), `ArgumentException` (bad key), `EndOfStreamException` (EOF). Server-side errors surface via the `E` header field.
- **JSON**: `JsonSerializerOptions` with `PropertyNamingPolicy = null` (single-letter attributes control names). Optional payloads typed `JsonElement?` (`.M`, `.Body`), read via `.GetString()`. Request metadata built as `Dictionary<string, ...>` then `JsonSerializer.SerializeToElement(...)`.
- **Binary/encoding**: big-endian ints via `System.Buffers.Binary.BinaryPrimitives.Write/ReadUInt32BigEndian`; hex via `Convert.ToHexString/FromHexString` (pubkey lowercased); base64 for nonce/signature; `Guid.NewGuid().ToString("N")[..16]` for 16-hex ids; `DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()` for timestamps.
- **Lifecycle**: `IDisposable` + `using var` at call sites; private ctor + static `ConnectAsync` factory for `SpxClient`.
- **Logging**: `Console.WriteLine` with `[*]` (info), `[+]` (success), `[!]` (error), `[?]` (unhandled) prefixes. No DI, no config files, no logging library.

## Important Files

- `SPXAgent/Program.cs` — entry point and orchestration; prints the public key that must be whitelisted server-side.
- `SPXAgent/SpxClient.cs` — TLS setup, AUTH/REG/PING state machine, frame dispatch (`HandleServerFrameAsync` is where command handlers go).
- `SPXAgent/Frame.cs` — protocol core: `SpxHeader` shape + framing; `Magic`, `Version`, `MaxHeaderLen` (64 KiB), `MaxPayloadLen` (256 MiB).
- `SPXAgent/AgentIdentity.cs` — key management; supports `SPX_AGENT_KEY` env var (64 hex chars = 32-byte seed) for stable identity, else generates a fresh keypair each run.

## Runtime/Tooling Preferences

- **Runtime**: .NET 8 (requires .NET SDK 8.x to build/run).
- **Package manager**: NuGet; single dependency `NSec.Cryptography 25.4.0` (libsodium native binaries are copied to `bin/<cfg>/net8.0/runtimes/<rid>/native/` at build).
- **OS**: currently developed/built on Windows; no platform-specific code in source (TLS is portable).
- No formatting/linting tooling is wired up; follow the existing style manually.

## Testing & QA

- **No test project exists**; no test framework configured. `dotnet test` will report no test projects.
- Verify changes by building (`dotnet build agents.sln`) and running against a server (`dotnet run --project SPXAgent -- <host> <port>`); success is `[+] AUTH OK` → `[+] registered session: <id>` → recurring PING/PONG.
- If you add tests, create a new test project (e.g. `SPXAgent.Tests`, xUnit) and reference the agent project; none exists to extend today.

## Known Gotchas (from source review)

1. **TLS certificate is accept-all**: `SpxClient.ValidateServerCertificate` returns `true` unconditionally (skeleton). TODO: pin server cert / mTLS CA.
2. **Concurrent readers on one `SslStream`**: `HeartbeatAsync` (via `PingAsync`) and `RunAsync` both call `Frame.ReadAsync(_ssl)` concurrently; `PingAsync` handles stray frames itself, but concurrent reads can race on frame boundaries — fragile; a single read-loop dispatching to handlers is the likely fix.
3. **`Task.WhenAny` swallows the loser's exception**: only the first-completed task is observed; if the other faults (e.g. server disconnect → `EndOfStreamException`) its exception is unobserved. Also `HeartbeatAsync` returns on first ping error, cancelling the whole agent.
4. **CMD execution is a stub**: `CMD` frames are logged only; no `RES` reply, no handler registry. Wire handlers per the `spxMsgConstructors` comment (Ping, LsReq/Ls, ExecuteReq/Execute, …) before expecting real command support.
5. **`SpxHeader` field names are the wire contract**: single-letter `[JsonPropertyName]` mapping must stay in sync with the Go server (`server/c2/spx.go`); renaming breaks wire compatibility silently.
6. **Flags byte hard-coded to 0** in `Frame.WriteAsync` though the format defines 0x01=compressed / 0x02=close / 0x04=stream-cont.
7. **Identity is ephemeral**: without `SPX_AGENT_KEY`, a fresh keypair is generated each run, so the pubkey must be re-added to `server.yaml` `spx.authorized_keys` every run.
