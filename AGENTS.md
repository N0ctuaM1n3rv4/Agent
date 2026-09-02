# Repository Guidelines

## Project Overview

`SPXAgent` is a .NET 8 C# console agent that implements the **SPX wire protocol** — a Sliver-server C2 framing format. It connects to a server over TLS 1.2/1.3, authenticates with an Ed25519 challenge-response, registers, and then runs one of two lifecycles: **session mode** (persistent connection, single blocking read loop, server-pushed commands) or **beacon mode** (periodic check-in over a fresh connection: connect → register → fetch pending tasks → disconnect → sleep).

On top of the C2 baseline, the agent now implements a **filesystem command layer**: SPX `CMD` frames for `PwdReq`/`CdReq`/`LsReq`/`DownloadReq`/`UploadReq` are translated (`FsCommands`) into operations on a **raw NTFS reader/writer** (`SPXAgent/Ntfs/`) that reads and writes the volume directly at the sector level — bypassing the Windows filesystem stack and thus minifilter `CreateFile`/`ReadFile`/`WriteFile` monitoring. All filesystem state is reconstructed by parsing/rewriting on-disk NTFS structures (Boot Sector → `$MFT` → Records → Attributes → Runlists/Indexes).

The two authoritative contracts live in `docs/`:

- `docs/spx-protocol.md` — the byte-for-byte agent↔server wire contract (frame layout, JSON header fields, opcodes, AUTH/REG/PING/CMD-RES, command field definitions).
- `docs/ntfs-filesystem.md` — the NTFS module design: data structures, read path, write path, current consistency gaps, and the isolated-volume testing rules.

Development baseline: agent version string is still `"0.1-skeleton"`, no CI, no logging library, TLS server-cert pinning not yet wired. The NTFS **write path is implemented and verified by the standalone `NtfsVerify` harness on an isolated volume**, but the **live agent opens the volume read-only** — see Known Gotchas.

## Architecture & Data Flow

### Startup flow (`Program.cs` → `Main`)

```
args (host port [mode=session|beacon] [intervalSec=60] [jitterPercent=20]; defaults 127.0.0.1:9999)
  → new AgentIdentity()               # Ed25519 keypair (fresh, or SPX_AGENT_KEY seed)
  → print hex pubkey                  # must be added to server.yaml spx.authorized_keys
  → Console.CancelKeyPress → cts.Cancel()
  → mode == "session" ? RunSessionModeAsync : RunBeaconModeAsync
```

**Session mode** (`RunSessionModeAsync`):

```
SpxClient.ConnectAsync              # TCP → SslStream (TLS 1.2/1.3)
  → AuthenticateAsync               # AUTH: sign base64 nonce → reply M={pubkey,sig} → AUTH_OK
  → RegisterSessionAsync            # REG (c=0x0001, f=0x01 session mode) → REG_OK → SessionId
  → RunAsync(ct)                    # single blocking read loop until server closes / KillReq
```

**Beacon mode** (`RunBeaconModeAsync`): reconnect loop until `ct` cancelled or `KillReq` received.

```
beaconId = SPX_BEACON_ID env var, else generated Frame.NewId() (printed once)
loop:
  SpxClient.ConnectAsync → AuthenticateAsync
  → RegisterBeaconAsync(beaconId, intervalMs, jitterMs)   # REG f=0x02, S=beaconId
  → RunBeaconCheckinAsync                                 # send TASK check-in, read task batch, reply TASK_RES
  → sleep intervalMs ± jitter, repeat
```

- There is **no agent-side heartbeat**: session mode relies on the TCP/TLS connection for liveness (read loop ends on EOF/error); liveness probing is server-initiated via the `Ping` CMD.
- A single `SslStream` has **exactly one reader at a time** in both modes — the concurrent-reader race is structurally gone.

### Command handling (`SpxClient.HandleServerFrameAsync`)

- `PING` (frame type) → reply `PONG` echoing `i` (kept for protocol completeness; the agent never sends PING).
- `CMD` (session) / `TASK` (beacon) → `CoreCommands.Dispatch` first, then `FsCommands.Dispatch`:
  - `CoreCommands` handles `Ping` (echo body verbatim) and `KillReq` (returns an exit flag → `HandleServerFrameAsync` returns `false` → the read loop breaks; beacon mode propagates this out of the reconnect loop).
  - `FsCommands` handles `PwdReq`/`CdReq`/`LsReq`/`DownloadReq`/`UploadReq`/`RmReq`/`MkdirReq`/`MvReq`/`CpReq`/`ChmodReq`/`ChownReq`/`ChtimesReq`.
  - Replies: `RES` (`c=0x0101`) for session CMD, `TASK_RES` (`c=0x0201`, `s=beaconId`) for beacon TASK, with `r` = request `i`.
  - Beacon tasks that produce no response (e.g. `CdReq`) still send a completion `TASK_RES` (msg = request type, body `{}`) so the server marks the task done.
  - Command exceptions are logged, not fatal.
- `DATA` / `CLOSE` / `ERR` → logged only (no stream/tunnel transport wired yet).

### Filesystem layer (`FsCommands` → `NtfsFileSystem` → `NtfsVolume`)

- `FsCommands` is a static facade over a single shared `NtfsFileSystem Fs = new()` (opened **read-only**, first NTFS fixed volume or `C:`). It maps protojson request fields to `NtfsFileSystem` calls and serializes responses back to protojson (lowerCamelCase, `bytes` as base64, gzip for transfer).
- `NtfsFileSystem` is the public FS API: `Pwd`/`Cd`/`Ls`/`Cat` (read path) and `Write`/`MkDir`/`Rm`/`Mv`/`Cp` (write path). Read path is complete and verified; write path builds new MFT records, `FILE_NAME`/`DATA` attributes and directory index entries.
- `NtfsVolume` owns the `CreateFile` handle on the volume device (`\\.\X:`), sector-aligned raw reads, read-modify-write sector writes, and the `FSCTL_LOCK_VOLUME` / `FSCTL_UNLOCK_VOLUME` lifecycle required to raw-write a mounted volume.

### Module graph

```
Program
  ├── AgentIdentity            (crypto: Ed25519 sign / pubkey)
  └── SpxClient                (TLS transport + AUTH/REG + session/beacon read loops)
        ├── Frame / SpxHeader  (protocol framing + JSON header model)
        ├── AgentIdentity      (for AUTH signing)
        ├── CoreCommands       (Ping echo, KillReq shutdown)
        └── FsCommands         (FS CMD dispatch → NtfsFileSystem)
              └── SpxAgent.Ntfs.NtfsFileSystem
                    ├── NtfsVolume      (device I/O, fixup, lock)
                    ├── NtfsRecord      (MFT record parse)
                    ├── NtfsAttribute   (attribute + runlist parse)
                    ├── NtfsIndex       (directory index enumerate)
                    ├── NtfsWriter      (record/index build, fixup, insert)
                    └── NtfsEntry       (public entry record)
```

`Frame` is standalone (no internal deps). `SpxAgent.Ntfs.*` is self-contained and used by both `FsCommands` and the standalone `NtfsVerify` harness.

## Key Directories

|Path|Purpose|
|---|---|
|`SPXAgent/Program.cs`|Entry point; mode selection, session loop, beacon reconnect loop|
|`SPXAgent/AgentIdentity.cs`|Ed25519 identity (`_key`), pubkey export, signer|
|`SPXAgent/Frame.cs`|Binary framing + `SpxHeader` JSON model + size caps|
|`SPXAgent/SpxClient.cs`|TLS transport + AUTH/REG lifecycle + single read loop + CMD/TASK dispatch|
|`SPXAgent/CoreCommands.cs`|Core command dispatcher (`Ping` echo, `KillReq` shutdown)|
|`SPXAgent/FsCommands.cs`|FS CMD protojson ⇄ NtfsFileSystem adapter; gzip/tar helpers|
|`SPXAgent/Ntfs/NtfsVolume.cs`|Volume device open, sector I/O, USA fixup, `FSCTL_LOCK_VOLUME`|
|`SPXAgent/Ntfs/NtfsFileSystem.cs`|Public FS API (Pwd/Cd/Ls/Cat/Write/MkDir) over the volume|
|`SPXAgent/Ntfs/NtfsRecord.cs`|MFT record read + header constants|
|`SPXAgent/Ntfs/NtfsAttribute.cs`|Attribute parse (SI/FILE_NAME/DATA/INDEX_*), runlist decode|
|`SPXAgent/Ntfs/NtfsIndex.cs`|Directory index enumeration (INDEX_ROOT + INDX blocks)|
|`SPXAgent/Ntfs/NtfsWriter.cs`|Record/index construction, USA fixup apply, index insertion|
|`SPXAgent/Ntfs/NtfsEntry.cs`|Public directory-entry record (maps to sliver `FileInfo`)|
|`SPXAgent/SPXAgent.csproj`|Project file (net8.0, NSec.Cryptography 25.4.0, unsafe enabled)|
|`NtfsVerify/Program.cs`|Standalone write-path regression harness (run against an isolated volume)|
|`NtfsVerify/NtfsVerify.csproj`|Project file; references `SPXAgent.csproj`|
|`docs/spx-protocol.md`|Wire contract (authoritative for framing/fields/opcodes)|
|`docs/ntfs-filesystem.md`|NTFS module design + current-state/limitations|
|`agents.sln`|Solution (currently contains only the `SPXAgent` project)|

`bin/` and `obj/` are build artifacts (gitignored).

## Development Commands

- **Build agent**: `dotnet build agents.sln`
- **Run agent**: `dotnet run --project SPXAgent -- <host> <port> [mode] [intervalSec] [jitterPercent]` (artifact: `SPXAgent/bin/Debug/net8.0/spx-agent.exe`); `mode` is `session` (default) or `beacon`. Beacon mode honors `SPX_BEACON_ID` (16-hex) for a stable identity across restarts.
- **Build + run NTFS write-path harness**: `dotnet run --project NtfsVerify` (expects an isolated mounted NTFS volume, e.g. `Z:`; NOT in `agents.sln`, so it is not built by the solution build).
- **Package manager**: NuGet (restore happens via `dotnet build`/`dotnet run`).
- No lint/test commands exist. No formatter config, no `Directory.Build.props`, no `global.json`, no `nuget.config`.

## Code Conventions & Common Patterns

- **Target framework**: `net8.0`, SDK-style (`Microsoft.NET.Sdk`), `OutputType=Exe`, `AssemblyName=spx-agent`, `RootNamespace=SpxAgent`. **`<Nullable>enable</Nullable>`**, **`<ImplicitUsings>enable</ImplicitUsings>`**, **`<AllowUnsafeBlocks>true</AllowUnsafeBlocks>`** (unsafe is used in `NtfsVolume` for pinned sector buffers). Match all three in new files.
- **Naming**: PascalCase for public members/types; `_camelCase` for private readonly fields (`_key`, `_host`, `_port`, `_identity`, `_tcp`, `_ssl`, `_cwd`, `_vol`, `_handle`, `_writable`, `_locked`). One record (`NtfsEntry`); mutable POCOs (`SpxHeader`); tuple returns `(SpxHeader Header, byte[] Payload)`, `(string Msg, JsonElement Body)?`.
- **Async**: fully `async`/`await`; `CancellationToken` threaded through loops (`RunAsync`/`RunBeaconCheckinAsync`). Stream I/O uses `await WriteAsync`/`ReadAsync` with a custom partial-read loop (`Frame.ReadExactAsync`) — reuse it; never assume a single `ReadAsync` fills the buffer.
- **Error handling**: exceptions only, no Result types — `InvalidDataException` (protocol/auth failures), `InvalidOperationException` (oversized frames, read-only volume write), `ArgumentException` (bad key), `IOException` (FS path misses, seek/IO failures), `EndOfStreamException` (EOF). Server-side errors surface via the `E` header field.
- **JSON**: two distinct conventions —
  - Frame header: `JsonSerializerOptions` with `PropertyNamingPolicy = null` (single-letter `[JsonPropertyName]` attrs control names; must stay in sync with the Go server `server/c2/spx.go`).
  - Command bodies (`FsCommands`): `PropertyNamingPolicy = JsonNamingPolicy.CamelCase` + `DefaultIgnoreCondition = WhenWritingNull` (protojson lowerCamelCase). Optional bodies typed `JsonElement?`; request fields read via typed `GetString`/`GetInt64`/`GetBool`/`GetBytes` helpers (`bytes` = base64 string).
- **Binary/encoding**: big-endian ints via `System.Buffers.Binary.BinaryPrimitives`; NTFS on-disk structures are **little-endian** (`NtfsVolume.ReadU16/ReadU32/ReadU64`). Hex via `Convert.ToHexString/FromHexString` (pubkey lowercased); base64 for nonce/signature/`bytes` fields; `Guid.NewGuid().ToString("N")[..16]` for 16-hex ids; `DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()` for timestamps.
- **Lifecycle**: `IDisposable` + `using var` at call sites; private ctor + static `ConnectAsync` factory for `SpxClient`. `NtfsFileSystem`/`NtfsVolume` dispose the handle and unlock the volume on dispose.
- **Logging**: `Console.WriteLine` with `[*]` (info), `[+]` (success), `[!]` (error), `[?]` (unhandled) prefixes. No DI, no config files, no logging library.

## Important Files

- `SPXAgent/Program.cs` — entry point; prints the whitelisted public key, parses mode, owns the session loop and beacon reconnect loop.
- `SPXAgent/SpxClient.cs` — TLS setup, AUTH/REG state machine, the single read loop, and frame dispatch (`HandleServerFrameAsync` routes to `CoreCommands` then `FsCommands`).
- `SPXAgent/Frame.cs` — protocol core: `SpxHeader` shape + framing; `Magic`, `Version`, `MaxHeaderLen` (64 KiB), `MaxPayloadLen` (256 MiB).
- `SPXAgent/AgentIdentity.cs` — key management; supports `SPX_AGENT_KEY` env var (64 hex chars = 32-byte seed) for stable identity, else generates a fresh keypair each run.
- `SPXAgent/CoreCommands.cs` — core command dispatcher; the place to add protocol-level commands (e.g. a future in-memory assembly-execution message).
- `SPXAgent/FsCommands.cs` — the FS CMD dispatch table and protojson adapter; the place to add new filesystem commands.
- `SPXAgent/Ntfs/NtfsFileSystem.cs` + `NtfsVolume.cs` — the raw-volume FS engine; `NtfsVolume` owns all kernel32 P/Invoke (`CreateFile`, `SetFilePointerEx`, `ReadFile`/`WriteFile`, `DeviceIoControl`) and the `FSCTL_LOCK_VOLUME` gate.
- `NtfsVerify/Program.cs` — the only executable verification of the write path; run only against an isolated volume.

## Runtime/Tooling Preferences

- **Runtime**: .NET 8 (requires .NET SDK 8.x to build/run).
- **Package manager**: NuGet. External dependency: `NSec.Cryptography 25.4.0` (libsodium native binaries are copied to `bin/<cfg>/net8.0/runtimes/<rid>/native/` at build). `System.Formats.Tar` and `System.IO.Compression` are framework-provided (no extra package).
- **OS**: **Windows-only in practice.** The NTFS module and `NtfsVerify` depend on Windows P/Invoke (`kernel32.dll`: `CreateFile`/`SetFilePointerEx`/`ReadFile`/`WriteFile`/`DeviceIoControl`) and on `FSCTL_ALLOW_EXTENDED_DASD_IO` / `FSCTL_LOCK_VOLUME`. The TLS transport itself is portable, but the filesystem layer is not.
- No formatting/linting tooling is wired up; follow the existing style manually.

## Testing & QA

- **No formal test project exists** (no xUnit/NUnit); `dotnet test` will report no test projects.
- **C2/protocol verification** is by building (`dotnet build agents.sln`) and running against a server:
  - Session: `dotnet run --project SPXAgent -- <host> <port>`; success is `[+] AUTH OK` → `[+] registered session: <id>` → correct `RES` replies to CMD frames (`Ping` echo, `LsReq`, …), and clean exit on `KillReq`.
  - Beacon: `dotnet run --project SPXAgent -- <host> <port> beacon <intervalSec> <jitterPercent>`; success is a repeating connect → `[+] registered beacon: <id>` → check-in cycle, `TASK_RES` replies for queued tasks, and clean exit on `KillReq`.
- **NTFS write-path verification** is via `NtfsVerify` (`dotnet run --project NtfsVerify`), which exercises resident write, 2 MB non-resident write, 60-file multi-block index spill, rm, mv (same-dir + cross-dir), and cp against a **mounted isolated NTFS volume (e.g. `Z:`)**, with SHA-256/byte-equality self-consistency checks. It is a manual harness, not a unit-test suite.
- **Do not run the write path against a real system/data volume (`C:`/`D:`/etc.).** Per `docs/ntfs-filesystem.md`, the write path omits several consistency structures (`$MFT::$BITMAP`, `$Bitmap`, `$LogFile`, `$UsnJrnl`, parent `$SI` mtime), so even an isolated volume may be flagged dirty by Windows after a write. `rm` on large directories rebuilds the entire B-tree and orphans old leaf clusters (does not free them). Test only on a detached, disposable VHD and remove it afterward.
- If you add tests, create a new test project (e.g. `SPXAgent.Tests`, xUnit) and reference the agent project; none exists to extend today.

## Known Gotchas (from source review)

1. **TLS certificate is accept-all**: `SpxClient.ValidateServerCertificate` returns `true` unconditionally (skeleton). TODO: pin server cert / mTLS CA.
2. **Live agent FS layer is read-only**: `FsCommands` constructs `new NtfsFileSystem()` (writable=false). The write methods (`Write`/`MkDir`/`Rm`/`Mv`/`Cp`) therefore throw `InvalidOperationException("volume opened read-only")` at runtime in the agent; `FsCommands.Upload` catches it and reports `unwriteableFiles`. The write path itself works (proven by `NtfsVerify`, which opens `writable: true`), but it is **not enabled in the live agent**. Enabling it requires opening the volume writable (and thus locking it), which the agent currently never does.
3. **`SpxHeader` field names are the wire contract**: single-letter `[JsonPropertyName]` mapping must stay in sync with the Go server (`server/c2/spx.go`); renaming breaks wire compatibility silently. Authoritative reference: `docs/spx-protocol.md`.
4. **Frame flags byte is hard-coded to 0** in `Frame.WriteAsync` even though the format defines 0x01=compressed / 0x02=close / 0x04=stream-cont.
5. **Identity is ephemeral**: without `SPX_AGENT_KEY`, a fresh keypair is generated each run, so the pubkey must be re-added to `server.yaml` `spx.authorized_keys` every run. Beacon identity is similarly ephemeral unless `SPX_BEACON_ID` is set.
6. **NTFS write path is not consistency-complete**: it omits `$MFT::$BITMAP`, `$Bitmap`, `$LogFile`, `$UsnJrnl` updates (see `docs/ntfs-filesystem.md` §4.1). Raw writes can leave a mounted volume dirty; treat the write path as experimental and isolated-volume-only.
7. **`NtfsVerify` is not in `agents.sln`**: a bare `dotnet build agents.sln` does not build it; reference the project directly (`dotnet build NtfsVerify`).
8. **Command surface is intentionally narrow**: `Ping`, `KillReq`, and the FS set (`PwdReq`/`CdReq`/`LsReq`/`DownloadReq`/`UploadReq`/`RmReq`/`MkdirReq`/`MvReq`/`CpReq`/`ChmodReq`/`ChownReq`/`ChtimesReq`) are implemented. `Chmod` maps the owner-write bit to the Win32 `ReadOnly` attribute; `Chown` resolves `uid` via `NTAccount`→SID and calls `SetOwner`; `Chtimes` sets atime/mtime via `File.SetLastAccessTime`/`SetLastWriteTime`. `ExecuteReq`/`PsReq`/`ShellReq` (process spawn, process list, interactive shell) are deliberately **not** implemented — additional execution capability is planned to go through in-memory .NET assembly loading (`Assembly.Load` into a collectible `AssemblyLoadContext`), not process spawning. In session mode unknown messages fall through to the no-response path; in beacon mode they get a completion `TASK_RES`.
