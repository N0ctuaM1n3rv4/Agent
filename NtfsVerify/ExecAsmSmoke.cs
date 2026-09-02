using System.Text.Json;
using SpxAgent;
using SpxAgent.Exec;

// Smoke test for ExecuteAssemblyReq: compiles a tiny hello-world assembly at
// runtime (via a pre-built byte payload is not possible without Roslyn), so we
// instead build the payload from an already-compiled test assembly embedded as
// a resource is overkill. The simplest deterministic test: load the current
// test assembly itself is not useful. Instead, compile a minimal assembly with
// `dotnet build` is not available here. We therefore ship a base64 payload of a
// pre-compiled "HelloAsm.dll" produced by the harness build step — see below.
//
// For this smoke test we generate a minimal assembly using System.Reflection.Emit
// is not supported on .NET 8 for saving. The pragmatic approach: write a small
// C# file, compile it with csc (Roslyn ships with the SDK), feed the bytes to
// AssemblyRunner, and verify the captured output.

internal static class ExecAsmSmoke
{
    public static int Run()
    {
        int failures = 0;
        void Check(bool cond, string label)
        {
            Console.WriteLine((cond ? "[+] " : "[!] ") + label);
            if (!cond) failures++;
        }

        string tmp = Path.Combine(Path.GetTempPath(), "spx-exec-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmp);
        try
        {
            // 1. Compile a minimal hello-world assembly.
            string src = """
                public static class Hello
                {
                    public static void Main(string[] args)
                    {
                        System.Console.WriteLine("hello-from-asm " + string.Join(",", args));
                    }
                }
                """;
            string srcPath = Path.Combine(tmp, "Hello.cs");
            string dllPath = Path.Combine(tmp, "Hello.dll");
            File.WriteAllText(srcPath, src);

            string? cscDll = FindCsc();
            Check(cscDll is not null, "csc found");
            if (cscDll is null) return 1;

            // csc needs explicit references to the .NET runtime assemblies.
            string? runtimeDir = FindRuntimeDir();
            Check(runtimeDir is not null, "runtime dir found");
            if (runtimeDir is null) return 1;
            string refs = string.Join(" ", new[]
            {
                "System.Private.CoreLib.dll",
                "System.Runtime.dll",
                "System.Console.dll",
                "System.Private.Uri.dll",
            }.Select(r => $"-r:\"{Path.Combine(runtimeDir, r)}\""));

            var cscPsi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"\"{cscDll}\" -nostdlib -nologo {refs} -target:exe -out:\"{dllPath}\" \"{srcPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            var proc = System.Diagnostics.Process.Start(cscPsi)!;
            proc.WaitForExit();
            Check(proc.ExitCode == 0, "csc compiled");
            if (proc.ExitCode != 0)
            {
                Console.WriteLine(proc.StandardOutput.ReadToEnd());
                Console.WriteLine(proc.StandardError.ReadToEnd());
                return 1;
            }

            byte[] asmBytes = File.ReadAllBytes(dllPath);

            // 2. Execute via AssemblyRunner (direct API).
            byte[] output = AssemblyRunner.Execute(asmBytes, new[] { "a", "b" }, null, null);
            string text = System.Text.Encoding.UTF8.GetString(output);
            Check(text.Contains("hello-from-asm a,b"), $"entry-point output (got: {text.Trim()})");

            // 3. Execute via ExecCommands.Dispatch (protojson path).
            string b64 = Convert.ToBase64String(asmBytes);
            var req = JsonSerializer.Deserialize<JsonElement>(
                $$"""{"assembly":"{{b64}}","arguments":["x","y"]}""");
            var res = ExecCommands.Dispatch("ExecuteAssemblyReq", req);
            Check(res is ("ExecuteAssembly", _), "ExecuteAssemblyReq -> ExecuteAssembly");
            if (res is not null)
            {
                var outBytes = res.Value.Body.GetProperty("output").GetBytesFromBase64();
                string outText = System.Text.Encoding.UTF8.GetString(outBytes);
                Check(outText.Contains("hello-from-asm x,y"), $"dispatch output (got: {outText.Trim()})");
            }

            // 4. className/method path.
            string src2 = """
                public static class Lib
                {
                    public static string Echo(string s) => "echo:" + s;
                }
                """;
            string src2Path = Path.Combine(tmp, "Lib.cs");
            string dll2Path = Path.Combine(tmp, "Lib.dll");
            File.WriteAllText(src2Path, src2);
            var csc2 = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"\"{cscDll}\" -nostdlib -nologo {refs} -target:library -out:\"{dll2Path}\" \"{src2Path}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            var proc2 = System.Diagnostics.Process.Start(csc2)!;
            proc2.WaitForExit();
            byte[] libBytes = File.ReadAllBytes(dll2Path);
            byte[] out2 = AssemblyRunner.Execute(libBytes, new[] { "hi" }, "Lib", "Echo");
            Check(System.Text.Encoding.UTF8.GetString(out2).Contains("echo:hi"), "className/method output");

            // 5. Error path: bad assembly bytes.
            var badRes = ExecCommands.Dispatch("ExecuteAssemblyReq",
                JsonSerializer.Deserialize<JsonElement>("""{"assembly":"AAAA"}"""));
            Check(badRes is not null && badRes.Value.Body.TryGetProperty("response", out _), "bad assembly -> err response");
        }
        finally
        {
            try { Directory.Delete(tmp, recursive: true); } catch { }
        }

        Console.WriteLine(failures == 0 ? "[ALL] OK" : $"[FAIL] {failures} failures");
        return failures;
    }

    private static string? FindCsc()
    {
        // Roslyn csc.dll ships with the .NET SDK under sdk/<ver>/Roslyn/bincore.
        // We return the path to csc.dll; callers invoke it via `dotnet <csc.dll>`.
        string? dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        if (string.IsNullOrEmpty(dotnetRoot))
        {
            dotnetRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet");
        }
        string sdkDir = Path.Combine(dotnetRoot, "sdk");
        if (!Directory.Exists(sdkDir)) return null;
        foreach (string dir in Directory.GetDirectories(sdkDir).OrderByDescending(d => d))
        {
            string candidate = Path.Combine(dir, "Roslyn", "bincore", "csc.dll");
            if (File.Exists(candidate))
                return candidate;
        }
        return null;
    }

    private static string? FindRuntimeDir()
    {
        // The shared framework directory under Microsoft.NETCore.App.
        string? dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        if (string.IsNullOrEmpty(dotnetRoot))
        {
            dotnetRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet");
        }
        string fxDir = Path.Combine(dotnetRoot, "shared", "Microsoft.NETCore.App");
        if (!Directory.Exists(fxDir)) return null;
        // Pick the highest version.
        foreach (string dir in Directory.GetDirectories(fxDir).OrderByDescending(d => d))
            return dir;
        return null;
    }
}
