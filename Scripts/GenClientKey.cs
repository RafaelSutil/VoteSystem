using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Scripts
{
    public class GenClientKey
    {
        public static void GenCertsKeys()
        {
            //Generate a public/private key pair.  
            RSA rsa = RSA.Create();

            var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
            var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

            CertificateRequest req = new CertificateRequest($"CN=12044894408", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));


            var certificate = Convert.ToBase64String(cert.Export(X509ContentType.Cert));

            File.WriteAllTextAsync("..\\Certs\\ClientPublicKey.cer", publicKey);
            File.WriteAllTextAsync("..\\Certs\\ClientPrivateKey.cer", privateKey);
            File.WriteAllTextAsync("..\\Certs\\ClientCertificate.cer", certificate);
        }
    }
}
