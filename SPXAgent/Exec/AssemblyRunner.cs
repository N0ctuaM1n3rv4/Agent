using System.Reflection;
using System.Runtime.Loader;

namespace SpxAgent.Exec;

// In-memory .NET assembly execution: loads an assembly from raw bytes into a
// collectible AssemblyLoadContext, invokes its entry point (or a named
// class/method), captures stdout/stderr, and unloads the context afterwards.
public static class AssemblyRunner
{
    // Execute a managed assembly from bytes. When className/method are given
    // they take precedence over the assembly entry point. Returns the captured
    // console output.
    public static byte[] Execute(byte[] assemblyBytes, string[] args, string? className, string? method)
    {
        var alc = new AssemblyLoadContext(name: "spx-exec-" + Guid.NewGuid().ToString("N"), isCollectible: true);
        TextWriter originalOut = Console.Out;
        TextWriter originalErr = Console.Error;
        var sw = new StringWriter();
        try
        {
            Console.SetOut(sw);
            Console.SetError(sw);

            Assembly asm;
            using (var ms = new MemoryStream(assemblyBytes, writable: false))
                asm = alc.LoadFromStream(ms);

            object? result;
            if (!string.IsNullOrEmpty(className) && !string.IsNullOrEmpty(method))
            {
                Type? type = asm.GetType(className)
                    ?? throw new InvalidOperationException($"type not found: {className}");
                MethodInfo? mi = type.GetMethod(method,
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance)
                    ?? throw new InvalidOperationException($"method not found: {className}.{method}");

                object? instance = mi.IsStatic ? null : Activator.CreateInstance(type);
                object?[]? parameters = BuildParameters(mi, args);
                result = mi.Invoke(instance, parameters);
            }
            else
            {
                MethodInfo? entry = asm.EntryPoint
                    ?? throw new InvalidOperationException("assembly has no entry point; specify className/method");
                object?[]? parameters = BuildParameters(entry, args);
                result = entry.Invoke(null, parameters);
            }

            if (result is not null)
                sw.WriteLine(result);
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalErr);
            alc.Unload();
        }
        return System.Text.Encoding.UTF8.GetBytes(sw.ToString());
    }

    private static object?[]? BuildParameters(MethodInfo mi, string[] args)
    {
        var ps = mi.GetParameters();
        if (ps.Length == 0) return null;
        if (ps.Length == 1 && ps[0].ParameterType == typeof(string[]))
            return new object?[] { args };
        if (ps.Length == 1 && ps[0].ParameterType == typeof(string))
            return new object?[] { args.Length > 0 ? args[0] : "" };
        throw new NotSupportedException(
            $"unsupported entry-point signature: {mi.Name}({string.Join(", ", ps.Select(p => p.ParameterType.Name))})");
    }
}
