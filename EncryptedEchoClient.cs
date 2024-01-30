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

        serverPublicKey = Convert.FromBase64String(message);

        try
        {
            using RSA rsa = RSA.Create();
            // using RSACryptoServiceProvider rsa = new();
            rsa.ImportRSAPublicKey(serverPublicKey, out _);
        }
        catch (CryptographicException e)
        {
            throw new CryptographicException("Error: Invalid public key received from server: " + e.Message);
        }

    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input)
    {
        byte[] data = Encoding.UTF8.GetBytes(input);

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

        Logger.LogDebug("AES key in client: {key}", BitConverter.ToString(aes.Key));
        Logger.LogDebug("Message right after encryption: {message}", BitConverter.ToString(encryptedInput));

        // Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        using HMACSHA256 hmac = new();
        byte[] messageHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));

        // Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        byte[] aesKey = aes.Key;
        byte[] hmacKey = hmac.Key;

        byte[]? aesKeyEncrypted = null;
        byte[]? hmacKeyEncrypted = null;

        try
        {
            // Create a new instance of RSA
            using RSA rsa = RSA.Create();

            // Import the RSA Key information. This only needs
            // to include the public key information.
            rsa.ImportRSAPublicKey(serverPublicKey, out _);

            // Encrypt the byte array with OAEP padding
            aesKeyEncrypted = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
            hmacKeyEncrypted = rsa.Encrypt(hmacKey, RSAEncryptionPadding.OaepSHA256);
            // hmacKeyEncrypted = rsa.Encrypt(hmacKey, RSAEncryptionPadding.OaepSHA256);
            // hmacKeyEncrypted = rsa.Encrypt(hmacKey, RSAEncryptionPadding.CreateOaep(HashAlgorithmName.SHA256));
        }
        catch (CryptographicException e)
        {
            throw new CryptographicException("Error: Unable to encrypt AES and HMAC keys: " + e.Message);
        }

        // Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new EncryptedMessage(...);
        // return JsonSerializer.Serialize(message);
        EncryptedMessage encryptedMessage = new(aesKeyEncrypted, aes.IV, encryptedInput, hmacKeyEncrypted, messageHash);

        Logger.LogDebug("Hash in client before sending: {hash}", Encoding.UTF8.GetString(encryptedMessage.HMAC));

        return JsonSerializer.Serialize(encryptedMessage);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input)
    {
        // todo: Step 1: Deserialize the message.
        // var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);
        SignedMessage message = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(serverPublicKey, out _);
        if (!rsa.VerifyData(message.Message, message.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        {
            throw new InvalidSignatureException("Error: The signature on the server response was invalid");
        }

        // todo: Step 3: Return the message from the server.
        // return Settings.Encoding.GetString(signedMessage.Message);
        return Encoding.UTF8.GetString(message.Message);
    }
}