using System.Text.Json;

namespace SpxAgent;

// Core SPX command handlers that are not filesystem-specific.
// Called before FsCommands so the agent can reply to protocol-level messages
// (Ping liveness, KillReq shutdown) as well as dispatch future core commands.
public static class CoreCommands
{
    public static (string? Msg, JsonElement? Body, bool Exit) Dispatch(string msg, JsonElement? body)
    {
        return msg switch
        {
            "Ping" => (msg, body, Exit: false),
            "KillReq" => (null, null, Exit: true),
            _ => (null, null, Exit: false),
        };
    }
}
