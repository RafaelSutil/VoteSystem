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
    class GenServerCert
    {
        public static void GenCertsKeys()
        {
            //Generate a public/private key pair.  
            RSA rsa = RSA.Create();

            var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
            var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

            CertificateRequest req = new CertificateRequest($"CN=ElectionServer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
            
            


            var certificate = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            /*
            Console.WriteLine("ServerPublicKey:" + Convert.ToBase64String(cert.GetPublicKey()) + "\n");
            Console.WriteLine("ServerPublicKey:" + publicKey + "\n");
            Console.WriteLine("ServerCert:" + certificate + "\n");*/

            File.WriteAllTextAsync("..\\Certs\\ServerPublicKey.cer", publicKey);
            File.WriteAllTextAsync("..\\Certs\\ServerPrivateKey.cer", privateKey);
            File.WriteAllTextAsync("..\\Certs\\ServerCertificate.cer", certificate);
        }
    }
}
