using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SpxAgent.Ntfs;

// Raw NTFS volume access: opens the volume device (\\.\X:) and reads/writes
// sectors directly. This bypasses the file-system stack entirely, so
// minifilter callbacks are never invoked for file data.
internal unsafe sealed class NtfsVolume : IDisposable
{
    // NTFS boot sector field offsets (see docs in spx-protocol reference).
    private const int OffBytesPerSector = 0x0B;   // u16
    private const int OffSectorsPerCluster = 0x0D; // u8
    private const int OffMftLcn = 0x30;            // u64
    private const int OffClustersPerFileRecord = 0x40; // i8 (signed)
    private const int OffClustersPerIndexBlock = 0x44; // i8 (signed)

    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagNoBuffering = 0x20000000;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FsctlAllowExtendedDasdIo = 0x00090083;
    private const uint FsctlLockVolume = 0x00090018;
    private const uint FsctlUnlockVolume = 0x00090019;

    private readonly SafeFileHandle _handle;
    private readonly bool _writable;
    private bool _locked;

    public int BytesPerSector { get; }
    public int SectorsPerCluster { get; }
    public long MftLcn { get; }
    public int ClusterSize => SectorsPerCluster * BytesPerSector;
    public long MftOffset => MftLcn * ClusterSize;
    public int RecordSize { get; }
    public int IndexBlockSize { get; }

    public string VolumePath { get; }

    private NtfsVolume(SafeFileHandle handle, bool writable, string volumePath, int bytesPerSector,
        int sectorsPerCluster, long mftLcn, int recordSize, int indexBlockSize)
    {
        _handle = handle;
        _writable = writable;
        VolumePath = volumePath;
        BytesPerSector = bytesPerSector;
        SectorsPerCluster = sectorsPerCluster;
        MftLcn = mftLcn;
        RecordSize = recordSize;
        IndexBlockSize = indexBlockSize;
    }

    // Open the first NTFS fixed volume found, or the given explicit volume path.
    public static NtfsVolume Open(string? explicitPath = null, bool writable = false)
    {
        string volumePath = explicitPath ?? FindFirstNtfsVolume() ?? @"\\.\C:";
        string devicePath = ToDevicePath(volumePath);
        uint access = GenericRead | (writable ? GenericWrite : 0);
        uint share = FileShareRead | FileShareWrite;

        SafeFileHandle handle = CreateFile(devicePath, access, share, IntPtr.Zero, OpenExisting,
            FileFlagNoBuffering | FileFlagWriteThrough, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException($"failed to open NTFS volume '{devicePath}': Win32 error {err}");
        }

        try
        {
            // Allow unaligned / extended DASD I/O past the partition end marker.
            AllowExtendedDasdIo(handle);

            byte[] boot = ReadRaw(handle, 0, 512);
            if (Encoding.ASCII.GetString(boot, 3, 8) != "NTFS    ")
                throw new InvalidDataException($"'{devicePath}' is not an NTFS volume (bad OEM id)");

            int bytesPerSector = ReadU16(boot, OffBytesPerSector);
            int sectorsPerCluster = boot[OffSectorsPerCluster];
            long mftLcn = (long)ReadU64(boot, OffMftLcn);
            if (bytesPerSector == 0 || sectorsPerCluster == 0 || mftLcn == 0)
                throw new InvalidDataException($"'{devicePath}': malformed NTFS boot sector");

            int clusterSize = sectorsPerCluster * bytesPerSector;
            int recordSize = DecodePowerOfTwoField(unchecked((sbyte)boot[OffClustersPerFileRecord]), clusterSize);
            int indexBlockSize = DecodePowerOfTwoField(unchecked((sbyte)boot[OffClustersPerIndexBlock]), clusterSize);

            var vol = new NtfsVolume(handle, writable, volumePath, bytesPerSector, sectorsPerCluster,
                mftLcn, recordSize, indexBlockSize);

            // Raw sector writes to a mounted volume require an exclusive lock
            // (FSCTL_LOCK_VOLUME); otherwise WriteFile fails with access denied.
            if (writable)
                vol.LockVolume();

            return vol;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    // Lock the volume exclusively so raw sector writes are permitted.
    public void LockVolume()
    {
        if (!_writable || _locked) return;
        if (!DeviceIoControl(_handle, FsctlLockVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new IOException($"FSCTL_LOCK_VOLUME failed: Win32 error {Marshal.GetLastWin32Error()}");
        _locked = true;
    }

    public void UnlockVolume()
    {
        if (!_locked) return;
        DeviceIoControl(_handle, FsctlUnlockVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
        _locked = false;
    }

    public static string? FindFirstNtfsVolume()
    {
        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.IsReady && string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                    return drive.Name.TrimEnd('\\'); // "C:"
            }
            catch (IOException)
            {
                // Skip drives that cannot be queried.
            }
        }
        return null;
    }

    private static string ToDevicePath(string volumePath)
    {
        // volumePath like "C:" -> "\\.\C:" (volume device, not file).
        string trimmed = volumePath.Trim().TrimEnd('\\');
        if (trimmed.StartsWith("\\\\.\\") || trimmed.StartsWith("\\\\?\\"))
            return trimmed;
        return @"\\.\" + trimmed;
    }

    // clusters_per_X is signed: positive = clusters, negative = 2^-n (i.e. size = 1 << -n).
    private static int DecodePowerOfTwoField(sbyte value, int clusterSize)
    {
        if (value > 0) return value * clusterSize;
        if (value < 0) return 1 << -value;
        return clusterSize;
    }

    // Read length bytes starting at absolute byte offset into the volume.
    // Reads are sector-aligned internally; NO_BUFFERING + EXTENDED_DASD_IO allow the slice.
    public byte[] ReadBytes(long offset, int length)
    {
        byte[] buffer = new byte[length];
        int done = 0;
        while (done < length)
        {
            int n = ReadAt(offset + done, buffer.AsSpan(done));
            if (n == 0) throw new EndOfStreamException($"NTFS volume EOF at 0x{offset + done:X}");
            done += n;
        }
        return buffer;
    }

    // Debug: report the file pointer set + bytes read for one aligned chunk.
    public (bool SeekOk, uint BytesRead, byte[] Data) DebugReadRaw(long offset, int length)
    {
        unsafe
        {
            int rounded = (int)((length + BytesPerSector - 1) / BytesPerSector * BytesPerSector);
            byte* mem = (byte*)NativeMemory.AlignedAlloc((nuint)rounded, (nuint)BytesPerSector);
            try
            {
                bool ok = SetFilePointerEx(_handle, offset, IntPtr.Zero, 0);
                uint br = 0;
                bool rd = ReadFile(_handle, mem, (uint)rounded, out br, IntPtr.Zero);
                byte[] data = new byte[Math.Min(length, (int)br)];
                new ReadOnlySpan<byte>(mem, data.Length).CopyTo(data);
                return (ok && rd, br, data);
            }
            finally
            {
                NativeMemory.AlignedFree(mem);
            }
        }
    }

    public void WriteBytes(long offset, ReadOnlySpan<byte> data)
    {
        if (!_writable)
            throw new InvalidOperationException("volume opened read-only");
        int done = 0;
        while (done < data.Length)
        {
            int n = WriteAt(offset + done, data.Slice(done));
            if (n <= 0) throw new IOException($"NTFS volume write failed at 0x{offset + done:X}");
            done += n;
        }
    }

    private int ReadAt(long offset, Span<byte> buffer)
    {
        if (buffer.Length == 0) return 0;
        // Allocate a sector-aligned staging buffer and copy into the caller span.
        int rounded = (int)((buffer.Length + BytesPerSector - 1) / BytesPerSector * BytesPerSector);
        long alignedOffset = offset / BytesPerSector * BytesPerSector;
        int leading = (int)(offset - alignedOffset);

        unsafe
        {
            byte* mem = (byte*)NativeMemory.AlignedAlloc((nuint)rounded, (nuint)BytesPerSector);
            try
            {
                if (!SetFilePointerEx(_handle, alignedOffset, IntPtr.Zero, 0 /*FILE_BEGIN*/))
                    throw new IOException($"NTFS volume seek failed at 0x{alignedOffset:X}: Win32 error {Marshal.GetLastWin32Error()}");
                uint bytesRead;
                if (!ReadFile(_handle, mem, (uint)rounded, out bytesRead, IntPtr.Zero))
                {
                    int err = Marshal.GetLastWin32Error();
                    throw new IOException($"NTFS volume read failed at 0x{offset:X}: Win32 error {err}");
                }
                int usable = (int)bytesRead - leading;
                if (usable < 0) usable = 0;
                if (usable > buffer.Length) usable = buffer.Length;
                if (usable > 0)
                    new ReadOnlySpan<byte>(mem + leading, usable).CopyTo(buffer);
                if (usable < buffer.Length)
                    buffer.Slice(usable).Clear();
                return usable;
            }
            finally
            {
                NativeMemory.AlignedFree(mem);
            }
        }
    }

    private int WriteAt(long offset, ReadOnlySpan<byte> data)
    {
        // Read-modify-write whole sectors: zero-padding a partial sector would
        // clobber the neighbouring bytes on disk.
        long alignedStart = offset / BytesPerSector * BytesPerSector;
        long alignedEnd = (offset + data.Length + BytesPerSector - 1) / BytesPerSector * BytesPerSector;
        int rounded = (int)(alignedEnd - alignedStart);
        int leading = (int)(offset - alignedStart);

        byte[] sector = ReadBytes(alignedStart, rounded);
        data.CopyTo(sector.AsSpan(leading));

        unsafe
        {
            byte* mem = (byte*)NativeMemory.AlignedAlloc((nuint)rounded, (nuint)BytesPerSector);
            try
            {
                new ReadOnlySpan<byte>(sector).CopyTo(new Span<byte>(mem, rounded));
                if (!SetFilePointerEx(_handle, alignedStart, IntPtr.Zero, 0 /*FILE_BEGIN*/))
                    throw new IOException($"NTFS volume seek failed at 0x{alignedStart:X}: Win32 error {Marshal.GetLastWin32Error()}");
                uint bytesWritten;
                if (!WriteFile(_handle, mem, (uint)rounded, out bytesWritten, IntPtr.Zero))
                {
                    int err = Marshal.GetLastWin32Error();
                    throw new IOException($"NTFS volume write failed at 0x{offset:X}: Win32 error {err}");
                }
                return data.Length;
            }
            finally
            {
                NativeMemory.AlignedFree(mem);
            }
        }
    }

    private static void AllowExtendedDasdIo(SafeFileHandle handle)
    {
        DeviceIoControl(handle, FsctlAllowExtendedDasdIo, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
    }

    private static byte[] ReadRaw(SafeFileHandle handle, long offset, int length)
    {
        if (offset != 0) throw new NotSupportedException("boot-sector read assumes offset 0");
        int rounded = (int)((length + 511) / 512 * 512);
        unsafe
        {
            byte* mem = (byte*)NativeMemory.AlignedAlloc((nuint)rounded, 512);
            try
            {
                uint bytesRead;
                if (!ReadFile(handle, mem, (uint)rounded, out bytesRead, IntPtr.Zero))
                    throw new IOException($"volume read failed: Win32 error {Marshal.GetLastWin32Error()}");
                byte[] result = new byte[length];
                new ReadOnlySpan<byte>(mem, length).CopyTo(result);
                return result;
            }
            finally
            {
                NativeMemory.AlignedFree(mem);
            }
        }
    }

    private static ushort ReadU16(ReadOnlySpan<byte> b, int off) =>
        (ushort)(b[off] | (b[off + 1] << 8));

    private static ulong ReadU64(ReadOnlySpan<byte> b, int off)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++) v |= (ulong)b[off + i] << (8 * i);
        return v;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(SafeFileHandle hFile, long liDistanceToMove,
        IntPtr lpNewFilePointer, uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(SafeFileHandle hFile, byte* lpBuffer, uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(SafeFileHandle hFile, byte* lpBuffer, uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    public void Dispose()
    {
        if (_locked)
            DeviceIoControl(_handle, FsctlUnlockVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
        _handle.Dispose();
    }
}
