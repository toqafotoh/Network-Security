using NetworkSecurityApp.Services;
using System.Security.Cryptography;
using System.Text;

public class AesEncryptionService : IEncryptionService
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public AesEncryptionService(IConfiguration config)
    {
        // Ensure the encryption key is 32 bytes long (256-bit) for AES-256
        _key = GetValidKey(config["Encryption:Key"]);

        // Ensure the initialization vector (IV) is exactly 16 bytes (128-bit)
        _iv = GetValidIv(config["Encryption:IV"]);
    }

    // Converts a string key into a 32-byte key using SHA-256 hash
    private byte[] GetValidKey(string key)
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
        }
    }

    // Validates and returns a 16-byte IV, throws if not exactly 16 bytes
    private byte[] GetValidIv(string iv)
    {
        var ivBytes = Encoding.UTF8.GetBytes(iv);

        if (ivBytes.Length == 16)
        {
            return ivBytes;
        }
        else
        {
            Console.WriteLine($"IV Length: {Encoding.UTF8.GetBytes(iv).Length}");
            throw new CryptographicException("The IV must be 16 bytes long.");
        }
    }

    // Encrypts a plain text string using AES encryption
    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;

        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var encrypted = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        // Return encrypted data as a Base64 string
        return Convert.ToBase64String(encrypted);
    }

    // Decrypts a Base64-encoded cipher text string back to plain text
    public string Decrypt(string cipherText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;

        var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        var cipherBytes = Convert.FromBase64String(cipherText);
        var decrypted = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

        // Return the decrypted string
        return Encoding.UTF8.GetString(decrypted);
    }
}
