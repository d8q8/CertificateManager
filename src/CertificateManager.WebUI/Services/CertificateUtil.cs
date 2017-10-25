using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace CertificateManager.WebUI.Services
{
    public static class CertificateUtil
    {
        /// <summary>
        /// 把Key转换为String
        /// </summary>
        /// <param name="key">.Net Private Key or Public Key的抽象类</param>
        /// <param name="startMarkLine"></param>
        /// <param name="endMarkLine"></param>
        /// <returns></returns>
        public static string GetString(AsymmetricKeyParameter key, string startMarkLine = "", string endMarkLine = "")
        {
            using (MemoryStream memoryStream = new MemoryStream())
            using (TextWriter streamWriter = new StreamWriter(memoryStream))
            {
                PemWriter pemWriter = new PemWriter(streamWriter);
                pemWriter.WriteObject(key);
                streamWriter.Flush();
                //return Encoding.ASCII.GetString(memoryStream.GetBuffer());
                return ConvertToString(memoryStream.GetBuffer(), startMarkLine, endMarkLine);
            }
        }

        public static AsymmetricKeyParameter readPrivateKey(string privateKeyFileName)
        {
            AsymmetricCipherKeyPair keyPair;

            using (var reader = new StringReader(privateKeyFileName))
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

            return keyPair.Private;
        }

        public static AsymmetricKeyParameter readPublicKey(string privateKeyFileName)
        {
            AsymmetricCipherKeyPair keyPair;

            using (var reader = new StringReader(privateKeyFileName))
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

            return keyPair.Public;
        }

        public static string GetString(X509Certificate2 cert, X509ContentType exportType = X509ContentType.Cert, string password = "")
        {
            return ConvertToString(cert.Export(exportType, password), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
        }

        private static string ConvertToString(byte[] key, string startMarkLine = "", string endMarkLine = "")
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine(startMarkLine);
            builder.AppendLine(Convert.ToBase64String(key, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine(endMarkLine);
            return builder.ToString();
        }
    }
}
