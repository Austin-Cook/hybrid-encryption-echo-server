using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

internal sealed class EncryptedEchoServer : EchoServerBase
{

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoServer> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoServer>()!;

    private byte[]? publicKeyPKCS1 = null;
    private byte[]? privateKeyPKCS1 = null;

    /// <inheritdoc />
    internal EncryptedEchoServer(ushort port) : base(port)
    {
        using RSA rsa = RSA.Create();

        // save the public and private keys in PKCS#1 format
        publicKeyPKCS1 = rsa.ExportRSAPublicKey();
        privateKeyPKCS1 = rsa.ExportRSAPrivateKey();
    }


    // todo: Step 1: Generate a RSA key (2048 bits) for the server.

    /// <inheritdoc />
    public override string GetServerHello()
    {
        // todo: Step 1: Send the public key to the client in PKCS#1 format.
        // Encode using Base64: Convert.ToBase64String

        // ensure the public key is set
        if (publicKeyPKCS1 == null)
        {
            throw new CryptographicException("Error: (GetServerHello) the public key is null");
        }

        string publicKeyPKCS1Base64 = Convert.ToBase64String(publicKeyPKCS1);

        return publicKeyPKCS1Base64;
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input)
    {
        // Step 1: Deserialize the message.
        // var message = JsonSerializer.Deserialize<EncryptedMessage>(input);
        EncryptedMessage encryptedMessage = JsonSerializer.Deserialize<EncryptedMessage>(input);

        // Step 2: Decrypt the message using hybrid encryption.

        // decrypt the keys
        byte[]? aesKey = null;
        byte[]? hmacKey = null;
        try
        {
            // Create a new instance of RSA
            using RSA rsa = RSA.Create();

            // Import the RSA Key information. This needs
            // to include the private key information.
            rsa.ImportRSAPrivateKey(privateKeyPKCS1, out _);

            // Decrypt the byte array with OAEP padding.
            aesKey = rsa.Decrypt(encryptedMessage.AesKeyWrap, RSAEncryptionPadding.OaepSHA256);
            hmacKey = rsa.Decrypt(encryptedMessage.HMACKeyWrap, RSAEncryptionPadding.OaepSHA256);

            Logger.LogDebug("aes key received by server: {key}", BitConverter.ToString(aesKey));
        }
        catch (CryptographicException e)
        {
            throw new CryptographicException("Error: (Server) Unable to decrypt the AES or HMAC key" + e.Message);
        }

        Logger.LogDebug("Message right before decryption: {message}", Encoding.UTF8.GetString(encryptedMessage.Message));

        // decrypt the message
        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = aesKey;
        aes.IV = encryptedMessage.AESIV;
        // Create a decryptor to perform the stream transform.
        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        // Create the streams used for decryption.
        using MemoryStream msDecrypt = new(encryptedMessage.Message);
        using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
        using StreamReader srDecrypt = new(csDecrypt);
        // Read the decrypted bytes from the decrypting stream
        // and place them in a string.
        string plaintext = srDecrypt.ReadToEnd();

        // Step 3: Verify the HMAC.
        // Throw an InvalidSignatureException if the received hmac is bad.
        using HMACSHA256 hmac = new(hmacKey);
        byte[] localHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(plaintext));

        Logger.LogDebug("Hash from client: {hash}", Encoding.UTF8.GetString(encryptedMessage.HMAC));
        Logger.LogDebug("Local hash      : {localHash}", Encoding.UTF8.GetString(localHash));

        // check for equality
        if (!localHash.SequenceEqual(encryptedMessage.HMAC))
        {
            throw new InvalidSignatureException("The two hashes are not equal");
        }

        // Step 4: Return the decrypted and verified message from the server.
        // return Settings.Encoding.GetString(decryptedMessage);
        return plaintext;
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input)
    {
        byte[] data = Encoding.UTF8.GetBytes(input);

        // todo: Step 1: Sign the message.
        // Use PSS padding with SHA256.
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKeyPKCS1, out _);
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // todo: Step 2: Put the data in an SignedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new SignedMessage(...);
        // return JsonSerializer.Serialize(message);
        SignedMessage message = new(data, signature);

        return JsonSerializer.Serialize(message);
    }
}