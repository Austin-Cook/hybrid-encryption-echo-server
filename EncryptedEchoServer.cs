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
        using RSACryptoServiceProvider rsa = new();

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
            Environment.Exit(0);
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
            // Create a new instance of RSACryptoServiceProvider.
            using RSACryptoServiceProvider rsa = new();
            // Import the RSA Key information. This needs
            // to include the private key information.
            rsa.ImportRSAPrivateKey(privateKeyPKCS1, out _);

            // Decrypt the byte array with OAEP padding.
            aesKey = rsa.Decrypt(encryptedMessage.AesKeyWrap, true);

            Console.WriteLine("aes key received by server: " + BitConverter.ToString(aesKey)); // .Replace("-", "")
            hmacKey = rsa.Decrypt(encryptedMessage.HMACKeyWrap, true);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.ToString());
            Environment.Exit(0);
        }


        Console.WriteLine("Message right before decryption: " + Encoding.Unicode.GetString(encryptedMessage.Message));

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

        // DELETEME
        Console.WriteLine("Plaintext: " + plaintext);


        // Step 3: Verify the HMAC.
        // Throw an InvalidSignatureException if the received hmac is bad.
        using HMACSHA256 hmac = new(hmacKey);
        byte[] localHash = hmac.ComputeHash(Encoding.Unicode.GetBytes(plaintext));
        Console.WriteLine("Hash from client: " + Encoding.Unicode.GetString(encryptedMessage.HMAC));
        Console.WriteLine("Local hash      : " + Encoding.Unicode.GetString(localHash));

        // check for equality
        bool match = true;
        if (localHash.Length != encryptedMessage.HMAC.Length)
        {
            match = false;
        }
        for (int i = 0; i < localHash.Length; i++)
        {
            if (localHash[i] != encryptedMessage.HMAC[i])
            {
                match = false;
                Console.WriteLine("inequality found: " + localHash[i] + ", " + encryptedMessage.HMAC[i]);
            }
        }
        if (!match)
        {
            throw new InvalidSignatureException("The two hashes are not equal");
        }
        // if (!localHash.SequenceEqual(encryptedMessage.HMAC)) {
        //     throw new InvalidSignatureException("The two hashes are not equal");
        // }

        // Step 4: Return the decrypted and verified message from the server.
        // return Settings.Encoding.GetString(decryptedMessage);

        return plaintext;
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input)
    {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Sign the message.
        // Use PSS padding with SHA256.

        // todo: Step 2: Put the data in an SignedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new SignedMessage(...);
        // return JsonSerializer.Serialize(message);

        return input;
    }
}