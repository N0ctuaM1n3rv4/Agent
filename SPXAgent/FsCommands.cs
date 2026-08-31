using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Serialization;
using SpxAgent.Ntfs;

namespace SpxAgent;

// Translates SPX CMD frames (protojson body) into NtfsFileSystem calls and
// returns the RES payload (response type name + protojson body), or null when
// the command expects no response (CdReq). Field names follow the SPX contract
// docs/spx-protocol.md (protojson lowerCamelCase).
public static class FsCommands
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly NtfsFileSystem Fs = new();

    public static (string Msg, JsonElement Body)? Dispatch(string msg, JsonElement? body)
    {
        return msg switch
        {
            "PwdReq" => Pwd(),
            "CdReq" => Cd(body),
            "LsReq" => Ls(body),
            "DownloadReq" => Download(body),
            "UploadReq" => Upload(body),
            _ => null,
        };
    }

    private static (string, JsonElement)? Pwd()
    {
        var payload = new Dictionary<string, object> { ["path"] = Fs.Pwd() };
        return ("Pwd", JsonSerializer.SerializeToElement(payload, JsonOpts));
    }

    private static (string, JsonElement)? Cd(JsonElement? body)
    {
        // CdReq only mutates the agent cwd; no response body per contract.
        string path = GetString(body, "path") ?? Fs.Pwd();
        Fs.Cd(path);
        return null;
    }

    private static (string, JsonElement)? Ls(JsonElement? body)
    {
        string path = GetString(body, "path") ?? Fs.Pwd();
        var files = new List<object>();
        bool exists;
        try
        {
            foreach (NtfsEntry e in Fs.Ls(path))
            {
                files.Add(new Dictionary<string, object>
                {
                    ["name"] = e.Name,
                    ["isDir"] = e.IsDir,
                    ["size"] = e.Size,
                    ["modTime"] = e.ModTimeUnix,
                    ["mode"] = e.Mode,
                    ["link"] = e.Link ?? "",
                    ["uid"] = e.Uid ?? "",
                    ["gid"] = e.Gid ?? "",
                });
            }
            exists = true;
        }
        catch (IOException)
        {
            exists = false;
        }

        TimeZoneInfo tz = TimeZoneInfo.Local;
        string tzName = tz.IsDaylightSavingTime(DateTime.Now) && tz.DaylightName.Length > 0
            ? tz.DaylightName : tz.StandardName;
        var payload = new Dictionary<string, object>
        {
            ["path"] = path,
            ["exists"] = exists,
            ["files"] = files,
            ["timezone"] = tzName,
            ["timezoneOffset"] = (int)tz.GetUtcOffset(DateTime.Now).TotalSeconds,
        };
        return ("Ls", JsonSerializer.SerializeToElement(payload, JsonOpts));
    }

    private static (string, JsonElement)? Download(JsonElement? body)
    {
        string path = GetString(body, "path") ?? Fs.Pwd();
        long start = GetInt64(body, "start") ?? 0;
        long stop = GetInt64(body, "stop") ?? 0;
        bool recurse = GetBool(body, "recurse") ?? false;
        long maxBytes = GetInt64(body, "maxBytes") ?? 0;
        long maxLines = GetInt64(body, "maxLines") ?? 0;
        bool restrictedToFile = GetBool(body, "restrictedToFile") ?? false;

        // Single-file download: read content, gzip it.
        try
        {
            byte[] content = Fs.Cat(path, start, stop, maxBytes, maxLines);
            byte[] gz = Gzip(content);
            var payload = new Dictionary<string, object>
            {
                ["path"] = path,
                ["encoder"] = "gzip",
                ["exists"] = true,
                ["start"] = start,
                ["stop"] = stop,
                ["data"] = gz,
                ["isDir"] = false,
                ["readFiles"] = 1,
                ["unreadableFiles"] = 0,
            };
            return ("Download", JsonSerializer.SerializeToElement(payload, JsonOpts));
        }
        catch (NotSupportedException ex)
        {
            // Directories / large files need tar/archive handling.
            var err = new Dictionary<string, object>
            {
                ["path"] = path,
                ["exists"] = true,
                ["isDir"] = true,
                ["readFiles"] = 0,
                ["unreadableFiles"] = 0,
                ["response"] = new Dictionary<string, object> { ["err"] = ex.Message },
            };
            return ("Download", JsonSerializer.SerializeToElement(err, JsonOpts));
        }
        catch (IOException)
        {
            var err = new Dictionary<string, object>
            {
                ["path"] = path,
                ["exists"] = false,
                ["isDir"] = false,
                ["readFiles"] = 0,
                ["unreadableFiles"] = 0,
                ["response"] = new Dictionary<string, object> { ["err"] = "no such file" },
            };
            return ("Download", JsonSerializer.SerializeToElement(err, JsonOpts));
        }
    }

    private static (string, JsonElement)? Upload(JsonElement? body)
    {
        string path = GetString(body, "path") ?? Fs.Pwd();
        string encoder = GetString(body, "encoder") ?? "";
        byte[] data = GetBytes(body, "data") ?? Array.Empty<byte>();
        string? fileName = GetString(body, "fileName");
        bool overwrite = GetBool(body, "overwrite") ?? false;

        byte[] plain = encoder == "gzip" ? Gunzip(data) : data;
        int written = 0;
        int unwriteable = 0;
        try
        {
            // Directory uploads come as tar.gz; expand into the target dir.
            if (encoder == "gzip" && LooksLikeTar(plain))
            {
                int filesWritten = ExtractTar(plain, path, overwrite);
                written = filesWritten;
            }
            else
            {
                // Single file upload: path is the destination, or directory + fileName.
                string dest = path;
                if (!string.IsNullOrEmpty(fileName) && EndsWithSeparator(dest))
                    dest = dest + fileName;
                try
                {
                    Fs.Write(dest, plain, overwrite);
                    written = 1;
                }
                catch (Exception)
                {
                    unwriteable = 1;
                }
            }
        }
        catch (Exception)
        {
            unwriteable = 1;
        }

        var payload = new Dictionary<string, object>
        {
            ["path"] = path,
            ["writtenFiles"] = written,
            ["unwriteableFiles"] = unwriteable,
        };
        return ("Upload", JsonSerializer.SerializeToElement(payload, JsonOpts));
    }

    // ---------- helpers ----------

    private static string? GetString(JsonElement? body, string name)
    {
        if (body is not JsonElement el || el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(name, out JsonElement v)) return null;
        return v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString();
    }

    private static long? GetInt64(JsonElement? body, string name)
    {
        if (body is not JsonElement el || el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(name, out JsonElement v)) return null;
        return v.TryGetInt64(out long n) ? n : null;
    }

    private static bool? GetBool(JsonElement? body, string name)
    {
        if (body is not JsonElement el || el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(name, out JsonElement v)) return null;
        return v.ValueKind == JsonValueKind.True ? true : v.ValueKind == JsonValueKind.False ? false : null;
    }

    private static byte[]? GetBytes(JsonElement? body, string name)
    {
        if (body is not JsonElement el || el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(name, out JsonElement v)) return null;
        // protojson encodes bytes as base64.
        return v.ValueKind == JsonValueKind.String ? Convert.FromBase64String(v.GetString()!) : null;
    }

    private static byte[] Gzip(byte[] data)
    {
        using var outStream = new MemoryStream();
        using (var gz = new GZipStream(outStream, CompressionLevel.Fastest, leaveOpen: true))
            gz.Write(data, 0, data.Length);
        return outStream.ToArray();
    }

    private static byte[] Gunzip(byte[] data)
    {
        using var inStream = new MemoryStream(data);
        using var gz = new GZipStream(inStream, CompressionMode.Decompress);
        using var outStream = new MemoryStream();
        gz.CopyTo(outStream);
        return outStream.ToArray();
    }

    private static bool LooksLikeTar(byte[] data)
    {
        // ustar header magic at offset 257.
        return data.Length > 262 &&
               data[257] == (byte)'u' && data[258] == (byte)'s' && data[259] == (byte)'t' &&
               data[260] == (byte)'a' && data[261] == (byte)'r';
    }

    private static int ExtractTar(byte[] data, string destDir, bool overwrite)
    {
        int written = 0;
        using var ms = new MemoryStream(data);
        using var reader = new System.Formats.Tar.TarReader(ms, leaveOpen: false);
        while (reader.GetNextEntry() is { } entry)
        {
            string name = entry.Name.Replace('/', '\\').TrimStart('\\');
            if (string.IsNullOrEmpty(name)) continue;
            string target = destDir.TrimEnd('\\') + "\\" + name;
            if (entry.EntryType == System.Formats.Tar.TarEntryType.Directory)
            {
                // Create the directory through the raw NTFS writer.
                try { Fs.MkDir(target); } catch (Exception) { /* skip unwriteable dir */ }
                continue;
            }
            using var entryStream = entry.DataStream ?? Stream.Null;
            using var buffer = new MemoryStream();
            entryStream.CopyTo(buffer);
            try
            {
                Fs.Write(target, buffer.ToArray(), overwrite, autoCreateDirs: true);
                written++;
            }
            catch (Exception)
            {
                // skip unwriteable file
            }
        }
        return written;
    }

    private static bool EndsWithSeparator(string path) =>
        path.EndsWith('\\') || path.EndsWith('/');
}
