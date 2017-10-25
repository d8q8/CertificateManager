namespace CertificateManager.WebUI.Models.CertificateModels
{
    public class GenerateCertificateWithAutoPrivateKeyAndPublicKeyViewModel
    {
        public string CertificatePEMFormat { get; internal set; }
        public string PublicKey { get; internal set; }
        public string PrivateKey { get; internal set; }
    }

    public class RootCaPrivateKeyAndCertificateChain
    {
        public string PrivateKey { get; set; }
        /// <summary>
        /// PEM格式可以以.pem或者.crt为后缀， 基本上他俩等同
        /// </summary>
        public string CertificatePEMFormat { get; set; }
        public string PublicKey { get; set; }
        public string DeviceCertificate { get; set; }
        public string DevicePrivateKey { get; set; }
        public string DevicePublicKey { get; set; }
    }
}