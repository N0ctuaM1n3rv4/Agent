using System.Text.Json;
using SpxAgent;

// Smoke test for the Win32 metadata commands (Chmod/Chown/Chtimes) that go
// through System.IO rather than the raw NTFS write path. Invoked via
// `dotnet run --project NtfsVerify -- --smoke-meta` (no VHD required).
internal static class MetaCmdSmoke
{
    public static int Run()
    {
        string tmp = Path.Combine(Path.GetTempPath(), "spx-meta-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmp);
        string file = Path.Combine(tmp, "f.txt");
        File.WriteAllText(file, "x");
        string dir = Path.Combine(tmp, "sub");
        Directory.CreateDirectory(dir);
        string inner = Path.Combine(dir, "inner.txt");
        File.WriteAllText(inner, "y");

        int failures = 0;
        void Check(bool cond, string label)
        {
            Console.WriteLine((cond ? "[+] " : "[!] ") + label);
            if (!cond) failures++;
        }

        static JsonElement Req(string json) => JsonSerializer.Deserialize<JsonElement>(json);
        static string Esc(string s) => s.Replace("\\", "\\\\");

        try
        {
            // Chtimes
            var r1 = FsCommands.Dispatch("ChtimesReq", Req($$"""{"path":"{{Esc(file)}}","atime":"1000000000","mtime":"1000000000"}"""));
            Check(r1 is ("Chtimes", _), "ChtimesReq -> Chtimes");
            Check(File.GetLastWriteTime(file) == DateTimeOffset.FromUnixTimeSeconds(1000000000).LocalDateTime, "mtime applied");

            // Chmod: 0444 -> readonly
            var r2 = FsCommands.Dispatch("ChmodReq", Req($$"""{"path":"{{Esc(file)}}","fileMode":"0444"}"""));
            Check(r2 is ("Chmod", _), "ChmodReq -> Chmod");
            Check((File.GetAttributes(file) & FileAttributes.ReadOnly) != 0, "readonly applied");
            // Chmod back: 0644 -> writable
            var r2b = FsCommands.Dispatch("ChmodReq", Req($$"""{"path":"{{Esc(file)}}","fileMode":"0644"}"""));
            var fi = new FileInfo(file);
            fi.Refresh();
            Check((fi.Attributes & FileAttributes.ReadOnly) == 0, "readonly cleared");

            // Chmod recursive on dir
            FsCommands.Dispatch("ChmodReq", Req($$"""{"path":"{{Esc(dir)}}","fileMode":"0444","recursive":true}"""));
            Check((File.GetAttributes(inner) & FileAttributes.ReadOnly) != 0, "recursive readonly applied");
            FsCommands.Dispatch("ChmodReq", Req($$"""{"path":"{{Esc(dir)}}","fileMode":"0644","recursive":true}"""));

            // Chown to current user
            string user = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            var r4 = FsCommands.Dispatch("ChownReq", Req($$"""{"path":"{{Esc(file)}}","uid":"{{Esc(user)}}"}"""));
            Check(r4 is ("Chown", _), "ChownReq -> Chown");
            var fsAcl = new FileInfo(file).GetAccessControl();
            Check(fsAcl.GetOwner(typeof(System.Security.Principal.NTAccount))!.ToString() == user, "owner applied");

            // Chown bad user -> err in response
            var r5 = FsCommands.Dispatch("ChownReq", Req($$"""{"path":"{{Esc(file)}}","uid":"NoSuchUser__xyz"}"""));
            Check(r5 is ("Chown", _), "Chown bad user -> Chown response");
            Check(r5!.Value.Body.GetProperty("response").GetProperty("err").GetString()!.Length > 0, "err field present");

            // Chtimes nonexistent -> err
            var r6 = FsCommands.Dispatch("ChtimesReq", Req($$"""{"path":"{{Esc(Path.Combine(tmp, "nope.txt"))}}","atime":"1","mtime":"1"}"""));
            Check(r6!.Value.Body.GetProperty("response").GetProperty("err").GetString()!.Contains("no such"), "chtimes missing file err");
        }
        finally
        {
            try { FsCommands.Dispatch("ChmodReq", Req($$"""{"path":"{{Esc(dir)}}","fileMode":"0777","recursive":true}""")); } catch { }
            try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
            try { Directory.Delete(tmp, recursive: true); } catch { }
        }

        Console.WriteLine(failures == 0 ? "[ALL] OK" : $"[FAIL] {failures} failures");
        return failures;
    }
}
