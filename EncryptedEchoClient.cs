using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase
{

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) { }

    private byte[]? serverPublicKey = null;

    /// <inheritdoc />
    public override void ProcessServerHello(string message)
    {
        // todo: Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.

        // Console.WriteLine(message);

        serverPublicKey = Convert.FromBase64String(message);

        try
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportRSAPublicKey(serverPublicKey, out _);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
            Environment.Exit(0);
        }

    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input)
    {
        byte[] data = Settings.Encoding.GetBytes(input);

        // Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.

        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        // create an encryptor to perform the stream transform
        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        // create the streams used for encryption
        using MemoryStream msEncrypt = new();
        using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
        using StreamWriter swEncrypt = new(csEncrypt);
        // write all data to the stream.
        swEncrypt.Write(input);
        swEncrypt.Flush();
        csEncrypt.FlushFinalBlock();
        byte[] encryptedInput = msEncrypt.ToArray();

        Console.WriteLine("aes key in client: " + BitConverter.ToString(aes.Key)); // .Replace("-", "")
        Console.WriteLine("Message right after encryption: " + BitConverter.ToString(encryptedInput));

        // Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        using HMACSHA256 hmac = new();
        byte[] messageHash = hmac.ComputeHash(Encoding.Unicode.GetBytes(input));

        // Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        byte[] aesKey = aes.Key;
        byte[] hmacKey = hmac.Key;

        byte[]? aesKeyEncrypted = null;
        byte[]? hmacKeyEncrypted = null;

        try
        {
            // Create a new instance of RSACryptoServiceProvider
            using RSACryptoServiceProvider rsa = new();

            // Import the RSA Key information. This only needs
            // to include the public key information.
            rsa.ImportRSAPublicKey(serverPublicKey, out _);

            // Encrypt the byte array with OAEP padding
            aesKeyEncrypted = rsa.Encrypt(aesKey, true);
            hmacKeyEncrypted = rsa.Encrypt(hmacKey, true);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
            Environment.Exit(0);
        }

        // Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new EncryptedMessage(...);
        // return JsonSerializer.Serialize(message);
        EncryptedMessage encryptedMessage = new(aesKeyEncrypted, aes.IV, encryptedInput, hmacKeyEncrypted, messageHash);
        Console.WriteLine("Hash in client before sending: " + Encoding.Unicode.GetString(encryptedMessage.HMAC));

        return JsonSerializer.Serialize(encryptedMessage);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input)
    {
        // todo: Step 1: Deserialize the message.
        // var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.

        // todo: Step 3: Return the message from the server.
        // return Settings.Encoding.GetString(signedMessage.Message);
        return input;
    }
}