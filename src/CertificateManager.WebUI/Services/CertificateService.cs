using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificateManager.WebUI.Services
{
    public class CertificateService
    {
        public X509Certificate2 GenerateRootCaAuthority(X509Name rootAuthorityName, out AsymmetricCipherKeyPair rootCaKeyPair, int keyStrength = 4096)
        {
            rootCaKeyPair = GenerateRsaPrivateAndPublicKeyPair(keyStrength);
            //privateKey = CertificateUtil.GetString(keypair.Private, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----");
            //publicKey = CertificateUtil.GetString(keypair.Public, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----");
            return GenerateCertificateBaseOnPrivateAndPublicKeyPair(rootAuthorityName, rootCaKeyPair);
        }

        //public string GenerateRootCaAuthorityInStringFormat(string rootAuthorityName, out string privateKey, out string publicKey, int keyStrength = 4096)
        //{
        //    var x509cert = GenerateRootCaAuthority(rootAuthorityName, out privateKey, out publicKey, keyStrength);
        //    return CertificateUtil.GetString(x509cert, X509ContentType.Cert);
        //}

        /// <summary>
        /// 以RSA方式生成一组公钥跟私钥
        /// </summary>
        /// <param name="keyStrength"></param>
        /// <param name="subjectString">"C=US, ST=NY, L=NY, O=IT, OU=IT, CN=xx.xx.com"</param>
        /// <param name="issuerString">"C=US, ST=NY, L=NY, O=IT, OU=IT, CN=Root CA"</param>
        public AsymmetricCipherKeyPair GenerateRsaPrivateAndPublicKeyPair(int keyStrength = 2048)
        {
            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);
            AsymmetricCipherKeyPair subjectKeyPair;
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            return subjectKeyPair;
        }

        /// <summary>
        /// 根据私钥生成证书
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        public X509Certificate2 GenerateCertificateBaseOnPrivateAndPublicKeyPair(X509Name subjectName, AsymmetricCipherKeyPair keyPair)
        {
            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, true, new ExtendedKeyUsage(KeyPurposeID.AnyExtendedKeyUsage));

            // Serial Number
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            X509Name subjectDN = subjectName;
            X509Name issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            DateTime notBefore = DateTime.UtcNow.Date;
            DateTime notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            certificateGenerator.SetPublicKey(keyPair.Public);


            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", keyPair.Private, random);

            // selfsign certificate
            Org.BouncyCastle.X509.X509Certificate certificate = certificateGenerator.Generate(signatureFactory);
            X509Certificate2 x509 = new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate));
            //x509.FriendlyName = subjectName;
            return x509;
        }

        public X509Certificate2 CreateSelfSignedCertificateBasedOnCertificateAuthorityPrivateKey(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey)
        {
            const int keyStrength = 2048;

            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", issuerPrivKey, random);

            // The Certificate Generator
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, true, new ExtendedKeyUsage(KeyPurposeID.AnyExtendedKeyUsage));

            // Serial Number
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            X509Name subjectDN = new X509Name("CN=" + subjectName);
            X509Name issuerDN = new X509Name("CN=" + issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);


            // Valid For
            DateTime notBefore = DateTime.UtcNow.Date;
            DateTime notAfter = notBefore.AddYears(2);
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // selfsign certificate
            Org.BouncyCastle.X509.X509Certificate certificate = certificateGenerator.Generate(signatureFactory);
            //var dotNetPrivateKey = ToDotNetKey((RsaPrivateCrtKeyParameters)subjectKeyPair.Private);

            // merge into X509Certificate2
            X509Certificate2 x509 = new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate));
            //x509.PrivateKey = dotNetPrivateKey;
            x509.FriendlyName = subjectName;

            return x509;
        }
        public X509Certificate2 Sign(Pkcs10CertificationRequestDelaySigned inputCSR, X509Name issuerName, AsymmetricKeyParameter issuerPrivKey, AsymmetricCipherKeyPair pair)
        {
            const int keyStrength = 2048;

            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", issuerPrivKey, random);

            // The Certificate Generator
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, true, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            // Serial Number
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            var csrInfo = inputCSR.GetCertificationRequestInfo();
            certificateGenerator.SetIssuerDN(issuerName);
            certificateGenerator.SetSubjectDN(csrInfo.Subject);

            // Valid For
            DateTime notBefore = DateTime.UtcNow.Date;
            DateTime notAfter = notBefore.AddYears(2);
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // selfsign certificate
            Org.BouncyCastle.X509.X509Certificate certificate = certificateGenerator.Generate(signatureFactory);
            //var dotNetPrivateKey = ToDotNetKey((RsaPrivateCrtKeyParameters)subjectKeyPair.Private);

            // merge into X509Certificate2
            X509Certificate2 x509 = new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate));
            //x509.PrivateKey = dotNetPrivateKey;
            //x509.FriendlyName = csrInfo.Subject;

            return x509;
        }
    }
}
