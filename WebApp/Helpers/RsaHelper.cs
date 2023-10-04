using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web;

namespace WebApp.Helpers
{
    public static class RsaHelper
    {
        public static string encrypt(string plainText)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            PemReader pr = new PemReader(
                //(StreamReader)File.OpenText("./Key/publicKey.pem") // 512 bit
                (StreamReader)File.OpenText(HttpContext.Current.Server.MapPath("~/Key/publicKey.pem"))
            );
            RsaKeyParameters keys = (RsaKeyParameters)pr.ReadObject();

            // Pure mathematical RSA implementation
            // RsaEngine eng = new RsaEngine();

            // PKCS1 v1.5 paddings
            // Pkcs1Encoding eng = new Pkcs1Encoding(new RsaEngine());

            // PKCS1 OAEP paddings
            OaepEncoding eng = new OaepEncoding(new RsaEngine());
            eng.Init(true, keys);

            int length = plainTextBytes.Length;
            int blockSize = eng.GetInputBlockSize();
            List<byte> cipherTextBytes = new List<byte>();
            for (int chunkPosition = 0;
                chunkPosition < length;
                chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, length - chunkPosition);
                cipherTextBytes.AddRange(eng.ProcessBlock(
                    plainTextBytes, chunkPosition, chunkSize
                ));
            }
            return Convert.ToBase64String(cipherTextBytes.ToArray());
        }

        public static string decrypt(string cipherText)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            PemReader pr = new PemReader(
                //(StreamReader)File.OpenText("./Key/privateKey.pem") // 512 bit
                (StreamReader)File.OpenText(HttpContext.Current.Server.MapPath("~/Key/privateKey.pem"))
            );
            AsymmetricCipherKeyPair keys = (AsymmetricCipherKeyPair)pr.ReadObject();

            // Pure mathematical RSA implementation
            // RsaEngine eng = new RsaEngine();

            // PKCS1 v1.5 paddings
            // Pkcs1Encoding eng = new Pkcs1Encoding(new RsaEngine());

            // PKCS1 OAEP paddings
            OaepEncoding eng = new OaepEncoding(new RsaEngine());
            eng.Init(false, keys.Private);

            int length = cipherTextBytes.Length;
            int blockSize = eng.GetInputBlockSize();
            List<byte> plainTextBytes = new List<byte>();
            for (int chunkPosition = 0;
                chunkPosition < length;
                chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, length - chunkPosition);
                plainTextBytes.AddRange(eng.ProcessBlock(
                    cipherTextBytes, chunkPosition, chunkSize
                ));
            }
            return Encoding.UTF8.GetString(plainTextBytes.ToArray());
        }
    }
}