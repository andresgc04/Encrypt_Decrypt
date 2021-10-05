using Microsoft.Analytics.Interfaces;
using Microsoft.Analytics.Interfaces.Streaming;
using Microsoft.Analytics.Types.Sql;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace EncryptAndDecrypt
{
    public class EncryptsAndDecrypts
    {
        public static string Encrypt(string source)
        {
            using (TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider())
            {
                using (MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider())
                {
                    byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes("Ag%04071997*"));
                    tripleDESCryptoService.Key = byteHash;
                    tripleDESCryptoService.Mode = CipherMode.ECB;
                    byte[] data = Encoding.UTF8.GetBytes(source);
                    return Convert.ToBase64String(tripleDESCryptoService.CreateEncryptor().TransformFinalBlock(data, 0, data.Length));
                }
            }
        }

        public static string Decrypt(string encrypt)
        {
            using (TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider())
            {
                using (MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider())
                {
                    byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes("Ag%04071997*"));
                    tripleDESCryptoService.Key = byteHash;
                    tripleDESCryptoService.Mode = CipherMode.ECB;
                    byte[] data = Convert.FromBase64String(encrypt);
                    return Encoding.UTF8.GetString(tripleDESCryptoService.CreateDecryptor().TransformFinalBlock(data, 0, data.Length));
                }
            }
        }
    }
}