using NSec.Cryptography;

namespace SpxAgent;

// Agent identity: Ed25519 keypair used for the SPX AUTH challenge-response.
// The hex public key must be added to the server's spx.authorized_keys list.
public sealed class AgentIdentity
{
    private readonly Key _key;

    public AgentIdentity()
    {
        // Reuse a stable identity when SPX_AGENT_KEY (64 hex chars = 32-byte
        // seed) is provided, otherwise generate a fresh keypair.
        string? seedHex = Environment.GetEnvironmentVariable("SPX_AGENT_KEY");
        if (!string.IsNullOrEmpty(seedHex))
        {
            byte[] seed = Convert.FromHexString(seedHex);
            if (seed.Length != SignatureAlgorithm.Ed25519.PrivateKeySize)
                throw new ArgumentException($"SPX_AGENT_KEY must be {SignatureAlgorithm.Ed25519.PrivateKeySize} bytes");
            _key = Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey);
        }
        else
        {
            _key = Key.Create(SignatureAlgorithm.Ed25519);
        }
    }

    public string PublicKeyHex => Convert.ToHexString(PublicKeyBytes).ToLowerInvariant();

    public byte[] PublicKeyBytes => _key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

    // Sign - Ed25519 signature over the server's challenge nonce (base64 out).
    public string SignBase64(byte[] nonce)
    {
        byte[] sig = SignatureAlgorithm.Ed25519.Sign(_key, nonce);
        return Convert.ToBase64String(sig);
    }
}
