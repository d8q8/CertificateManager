using CertificateManager.WebUI.Models.CertificateModels;
using CertificateManager.WebUI.Services;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificateManager.WebUI.Controllers
{
    public class CertificatesController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult GenerateRootPrivateKeyAndCertificate([FromServices]CertificateService certificateService)
        {
            RootCaPrivateKeyAndCertificateChain model = new RootCaPrivateKeyAndCertificateChain();
            AsymmetricCipherKeyPair rootCaKeyPair;
            string rootCaSubjectName = "AgileLabs Primary Root Ca";
            var rootCaX509Name = new X509Name($"C=UK, ST=NY, L=NY, O=MC, OU=IT Dept., CN={rootCaSubjectName}");
            var x509cert = certificateService.GenerateRootCaAuthority(rootCaX509Name, out rootCaKeyPair, keyStrength: 2048);

            model.CertificatePEMFormat = CertificateUtil.GetString(x509cert, X509ContentType.Cert).Replace(Environment.NewLine, "<br/>");
            model.PrivateKey = CertificateUtil.GetString(rootCaKeyPair.Private, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----").Replace(Environment.NewLine, "<br/>");
            model.PublicKey = CertificateUtil.GetString(rootCaKeyPair.Public, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----").Replace(Environment.NewLine, "<br/>");

            //generate device key
            var deviceKeyPair = certificateService.GenerateRsaPrivateAndPublicKeyPair(2048);
            model.DevicePrivateKey = CertificateUtil.GetString(deviceKeyPair.Private, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----").Replace(Environment.NewLine, "<br/>");
            model.DevicePublicKey = CertificateUtil.GetString(deviceKeyPair.Public, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----").Replace(Environment.NewLine, "<br/>");
            
            //generate csr
            //PKCS #10 Certificate Signing Request
            //Requested Certificate Name
            X509Name name = new X509Name("CN=agilelabs.net, C=NL");
            //Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest("SHA1WITHRSA", name, deviceKeyPair.Public, null, deviceKeyPair.Private);
            Pkcs10CertificationRequestDelaySigned csrDelaySigned = new Pkcs10CertificationRequestDelaySigned("SHA1WITHRSA", name, deviceKeyPair.Public, null);

            //sign csr and return certificate
            var deviceCert = certificateService.Sign(csrDelaySigned, rootCaX509Name, deviceKeyPair.Private, deviceKeyPair);

            model.DeviceCertificate = CertificateUtil.GetString(deviceCert, X509ContentType.Cert).Replace(Environment.NewLine, "<br/>");
            return View(model);
        }

        public IActionResult GenerateCertificateWithAutoPrivateKeyAndPublicKey()
        {
            var model = new GenerateCertificateWithAutoPrivateKeyAndPublicKeyViewModel();

            AsymmetricKeyParameter privateKey, publicKey;
            var cert = CreateCertificateAuthorityCertificate("*.agilelabs.net", out privateKey, out publicKey);

            // Export the certificate including the private key.
            byte[] certBytes = cert.Export(X509ContentType.Pkcs12);

            // To secure your exported certificate use the following overload of the Export function:
            byte[] certBytesWithPassword = cert.Export(X509ContentType.Pkcs12, "SecurePassword");

            //write x509 certificate to BASE-64 encoded .cer file
            model.CertificatePEMFormat = ExportToPEM(cert).Replace(Environment.NewLine, "<br/>");
            model.PublicKey = ExportKey(publicKey).Replace(Environment.NewLine, "<br/>");// ExportPublicKey(ToRSAParameters((RsaKeyParameters)publicKey))
            model.PrivateKey = ExportKey(privateKey).Replace(Environment.NewLine, "<br/>");

            ////Import test
            //X509Certificate2 certToImport = new X509Certificate2(certBytes);

            //// To mark it as exportable use the following constructor:
            //X509Certificate2 certToImportWithPassword = new X509Certificate2(certBytesWithPassword, "SecurePassword", X509KeyStorageFlags.Exportable);
            //// certToImport.HasPrivateKey must be true here!!

            ////Create a UnicodeEncoder to convert between byte array and string.
            //var ByteConverter = Encoding.UTF8;

            //string plainText = "这是一条被和谐的消息！";
            ////加密明文，获得密文
            //var EncryptText = RSAEncrypt(ByteConverter.GetBytes(plainText), ToRSAParameters((RsaKeyParameters)publicKey), false);  //PassWordHelper.Rsa(plainText);
            //Console.WriteLine(EncryptText);

            ////解密密文，获得明文
            //var DecryptText = RSADecrypt(EncryptText, ToRSAParameters((RsaPrivateCrtKeyParameters)privateKey), false); //PassWordHelper.UnRsa(EncryptText);
            //Console.WriteLine(ByteConverter.GetString(DecryptText));
            //Console.ReadKey();
            return View(model);
        }

        private string ExportKey(AsymmetricKeyParameter publicKey)
        {
            MemoryStream memoryStream = new MemoryStream();
            TextWriter streamWriter = new StreamWriter(memoryStream);
            PemWriter pemWriter = new PemWriter(streamWriter);
            pemWriter.WriteObject(publicKey);
            streamWriter.Flush();

            return Encoding.ASCII.GetString(memoryStream.GetBuffer());
        }

        public static X509Certificate2 CreateCertificateAuthorityCertificate(string subjectName, out AsymmetricKeyParameter CaPrivateKey, out AsymmetricKeyParameter CaPublicKey)
        {
            const int keyStrength = 2048;

            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            X509Name subjectDN = new X509Name(subjectName);
            X509Name issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            DateTime notBefore = DateTime.UtcNow.Date;
            DateTime notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", issuerKeyPair.Private, random);

            // selfsign certificate
            Org.BouncyCastle.X509.X509Certificate certificate = certificateGenerator.Generate(signatureFactory);
            var dotNetPrivateKey = ToDotNetKey((RsaPrivateCrtKeyParameters)subjectKeyPair.Private);

            //X509Certificate2 x509 = new X509Certificate2(certificate.GetEncoded());
            //x509.FriendlyName = subjectName;

            X509Certificate2 x509 = new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate));
            //x509.PrivateKey = dotNetPrivateKey; set private key for x509 is not supported for now
            x509.FriendlyName = subjectName;

            CaPrivateKey = issuerKeyPair.Private;
            CaPublicKey = subjectKeyPair.Public;

            return x509;
        }
        public static AsymmetricAlgorithm ToDotNetKey(RsaPrivateCrtKeyParameters privateKey)
        {
            var parameters = new RSAParameters()
            {
                Modulus = privateKey.Modulus.ToByteArrayUnsigned(),
                P = privateKey.P.ToByteArrayUnsigned(),
                Q = privateKey.Q.ToByteArrayUnsigned(),
                DP = privateKey.DP.ToByteArrayUnsigned(),
                DQ = privateKey.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKey.QInv.ToByteArrayUnsigned(),
                D = privateKey.Exponent.ToByteArrayUnsigned(),
                Exponent = privateKey.PublicExponent.ToByteArrayUnsigned()
            };

            return RSA.Create(parameters);
        }

        public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privateKey)
        {
            return new RSAParameters()
            {
                Modulus = privateKey.Modulus.ToByteArrayUnsigned(),
                P = privateKey.P.ToByteArrayUnsigned(),
                Q = privateKey.Q.ToByteArrayUnsigned(),
                DP = privateKey.DP.ToByteArrayUnsigned(),
                DQ = privateKey.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKey.QInv.ToByteArrayUnsigned(),
                D = privateKey.Exponent.ToByteArrayUnsigned(),
                Exponent = privateKey.PublicExponent.ToByteArrayUnsigned()
            };
        }

        public static RSAParameters ToRSAParameters(RsaKeyParameters publicKey)
        {
            return new RSAParameters()
            {
                Modulus = publicKey.Modulus.ToByteArrayUnsigned(),
                Exponent = publicKey.Exponent.ToByteArrayUnsigned()
            };
        }

        static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Import the RSA Key information. This only needs
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }

        }

        static public byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }

        }

        /// <summary>
        /// Export a certificate to a PEM format string
        /// </summary>
        /// <param name="cert">The certificate to export</param>
        /// <returns>A PEM encoded string</returns>
        public static string ExportToPEM(X509Certificate2 cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            //builder.Append(cert.Export(X509ContentType.Cert));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        public static string ExportPrivateKey(byte[] key)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(key, Base64FormattingOptions.InsertLineBreaks));
            //builder.Append(cert.Export(X509ContentType.Cert));
            builder.AppendLine("-----END PRIVATE KEY-----");

            return builder.ToString();
        }

        public static string ExportPublicKey(byte[] key)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN PUBLIC KEY-----");
            builder.AppendLine(Convert.ToBase64String(key, Base64FormattingOptions.InsertLineBreaks));
            //builder.Append(cert.Export(X509ContentType.Cert));
            builder.AppendLine("-----END PUBLIC KEY-----");

            return builder.ToString();
        }
    }
}