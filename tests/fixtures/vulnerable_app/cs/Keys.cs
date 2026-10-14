using System.Security.Cryptography;

class Keys {
    void Run() {
        using var rsa = RSA.Create(2048);
        var ct = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        using var ec = ECDiffieHellman.Create();
        using var md5 = MD5.Create();
    }
}
