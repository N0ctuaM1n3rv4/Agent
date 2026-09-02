using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SpxAgent.Ntfs;

static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data));

const int exitOk = 0;
const int exitAssertion = 1;
const int exitChkdsk = 2;
const int exitSetup = 3;

var opts = ParseArgs(args);
Console.WriteLine($"[*] VHD path: {opts.VhdPath}");
Console.WriteLine($"[*] VHD size : {opts.SizeMb} MB");

if (!IsAdmin())
{
    Console.WriteLine("[!] This test must run as Administrator (VHD mount + chkdsk require elevation).");
    return exitSetup;
}

string vhdPath = Path.GetFullPath(opts.VhdPath);
string logPath = Path.Combine(Path.GetTempPath(), $"ntfs-verify-chkdsk-{Path.GetFileNameWithoutExtension(vhdPath)}.log");

bool setupOk = false;
string driveLetter = string.Empty;
try
{
    driveLetter = SetupVhd(vhdPath, opts.SizeMb);
    if (string.IsNullOrEmpty(driveLetter))
    {
        Console.WriteLine("[!] Failed to mount VHD to a drive letter.");
        return exitSetup;
    }
    setupOk = true;

    Console.WriteLine("[*] Full regression: resident + non-resident + spill + overwrite");
    Directory.CreateDirectory($"{driveLetter}:\\winref");

    using (var fs = new NtfsFileSystem(driveLetter + ":", writable: true))
    {
        Console.WriteLine("[V2] MkDir \\testdir + resident file");
        if (!fs.MkDir("\\testdir")) throw new InvalidOperationException("MkDir failed");
        byte[] v2Data = Encoding.UTF8.GetBytes("this is a 33-byte resident file test.");
        if (fs.Write("\\testdir\\file1.txt", v2Data) != v2Data.Length) throw new InvalidOperationException("write len");
        if (!fs.Cat("\\testdir\\file1.txt").SequenceEqual(v2Data)) throw new InvalidOperationException("V2 readback");
        if (!fs.Ls("\\testdir").Any(e => e.Name == "file1.txt" && !e.IsDir)) throw new InvalidOperationException("V2 Ls");
        Console.WriteLine("[V2] OK");

        Console.WriteLine("[V6] Overwrite resident file (equal + shrink)");
        byte[] v6Equal = Encoding.UTF8.GetBytes("this is a 33-byte resident file test."); // same length
        if (fs.Write("\\testdir\\file1.txt", v6Equal) != v6Equal.Length) throw new InvalidOperationException("V6 equal len");
        if (!fs.Cat("\\testdir\\file1.txt").SequenceEqual(v6Equal)) throw new InvalidOperationException("V6 equal readback");

        byte[] v6Shrink = Encoding.UTF8.GetBytes("shrunk");
        if (fs.Write("\\testdir\\file1.txt", v6Shrink) != v6Shrink.Length) throw new InvalidOperationException("V6 shrink len");
        if (!fs.Cat("\\testdir\\file1.txt").SequenceEqual(v6Shrink)) throw new InvalidOperationException("V6 shrink readback");
        Console.WriteLine("[V6] OK");

        Console.WriteLine("[V4] Write \\testdir\\big.bin (2 MB non-resident)");
        byte[] big = new byte[2 * 1024 * 1024];
        Random.Shared.NextBytes(big);
        if (fs.Write("\\testdir\\big.bin", big) != big.Length) throw new InvalidOperationException("big write len");
        if (!fs.Cat("\\testdir\\big.bin").SequenceEqual(big)) throw new InvalidOperationException("V4 readback");
        Console.WriteLine($"[V4] OK (sha256={Sha256Hex(big)[..16]}...)");

        Console.WriteLine("[V5] 60 files into \\testdir (multi-block spill)");
        for (int i = 0; i < 60; i++)
        {
            string name = $"file_{i:D2}.txt";
            fs.Write($"\\testdir\\{name}", Encoding.UTF8.GetBytes($"content of {name}"));
        }
        var all = fs.Ls("\\testdir");
        int fileCount = all.Count(e => !e.IsDir && !e.Name.StartsWith("."));
        if (fileCount != 63) throw new InvalidOperationException($"expected 63, got {fileCount}");
        foreach (int i in new[] { 0, 29, 59 })
        {
            string name = $"file_{i:D2}.txt";
            if (!fs.Cat($"\\testdir\\{name}").SequenceEqual(Encoding.UTF8.GetBytes($"content of {name}")))
                throw new InvalidOperationException($"V5 spot check {name}");
        }
        Console.WriteLine("[V5] OK");
    }

    Console.WriteLine("[*] Running chkdsk /F /R ...");
    int chkdskExit = RunChkdsk(driveLetter, logPath);
    if (chkdskExit != 0)
    {
        Console.WriteLine($"[!] chkdsk failed with exit code {chkdskExit}; see {logPath}");
        return exitChkdsk;
    }
    Console.WriteLine($"[+] chkdsk passed (log: {logPath})");

    Console.WriteLine("[ALL] V2/V4/V5/V6 passed + chkdsk clean.");
    return exitOk;
}
catch (Exception ex)
{
    Console.WriteLine($"[!] Assertion failed: {ex}");
    return exitAssertion;
}
finally
{
    if (setupOk)
    {
        try
        {
            TeardownVhd(vhdPath, driveLetter);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] VHD teardown failed (manual cleanup may be needed): {ex.Message}");
        }
    }
}

static Options ParseArgs(string[] args)
{
    var opts = new Options
    {
        VhdPath = Path.Combine(Path.GetTempPath(), $"ntfs-verify-{Guid.NewGuid():N}.vhdx"),
        SizeMb = 64,
    };
    for (int i = 0; i < args.Length; i++)
    {
        switch (args[i].ToLowerInvariant())
        {
            case "--vhd-path":
                if (i + 1 < args.Length) opts.VhdPath = args[++i];
                break;
            case "--size-mb":
                if (i + 1 < args.Length && int.TryParse(args[++i], out int sz)) opts.SizeMb = sz;
                break;
        }
    }
    return opts;
}

static bool IsAdmin()
{
    if (OperatingSystem.IsWindows())
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
    return false;
}

static string SetupVhd(string vhdPath, int sizeMb)
{
    string script = $@"
$ErrorActionPreference = 'Stop'
$vhdPath = '{vhdPath.Replace("'", "''")}'
New-VHD -Path $vhdPath -SizeBytes {sizeMb}MB -Dynamic | Out-Null
$disk = Mount-VHD -Path $vhdPath -PassThru
Initialize-Disk -Number $disk.Number -PartitionStyle GPT
$part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
Format-Volume -Partition $part -FileSystem NTFS -Confirm:$false | Out-Null
$vol = Get-Volume -Partition $part
$vol.DriveLetter
";
    string output = RunPwsh(script);
    return output.Trim().TrimEnd('\r', '\n').Trim();
}

static void TeardownVhd(string vhdPath, string driveLetter)
{
    string script = $@"
$ErrorActionPreference = 'Stop'
$disk = Get-Disk | Where-Object {{ $_.Location -like '*{vhdPath.Replace("'", "''")}*' }}
if ($disk) {{ Dismount-VHD -Path '{vhdPath.Replace("'", "''")}' -ErrorAction SilentlyContinue }}
if (Test-Path '{vhdPath.Replace("'", "''")}') {{ Remove-Item '{vhdPath.Replace("'", "''")}' -Force -ErrorAction SilentlyContinue }}
";
    RunPwsh(script);
}

static int RunChkdsk(string driveLetter, string logPath)
{
    var psi = new ProcessStartInfo("chkdsk.exe", $"{driveLetter}: /F /R")
    {
        Verb = "runas",
        UseShellExecute = true,
        CreateNoWindow = true,
        WindowStyle = ProcessWindowStyle.Hidden,
    };
    var proc = Process.Start(psi);
    proc?.WaitForExit();
    int exit = proc?.ExitCode ?? -1;
    File.WriteAllText(logPath, $"chkdsk {driveLetter}: /F /R exited {exit}{Environment.NewLine}");
    return exit;
}

static string RunPwsh(string script)
{
    var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\"\"")}\"")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    var proc = Process.Start(psi)!;
    string stdout = proc.StandardOutput.ReadToEnd();
    string stderr = proc.StandardError.ReadToEnd();
    proc.WaitForExit();
    if (proc.ExitCode != 0)
    {
        throw new InvalidOperationException($"PowerShell failed (exit {proc.ExitCode}): {stderr}");
    }
    return stdout;
}

class Options
{
    public string VhdPath { get; set; } = string.Empty;
    public int SizeMb { get; set; }
}
