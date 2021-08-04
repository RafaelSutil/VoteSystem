using System;
using System.Security.Cryptography;
using System.Text;
using VoteProtocol;

namespace Client
{
    class Program
    {
        public static PClient client;
        static void Main(string[] args)
        {
            Console.WriteLine("Hello Client!");
            GenKeys();

            //Connect
            PClient.ConnectToServer(client.socket);
            //Handshake
            PClient.HandShake(client);
            //While com rcvMsg
            RequestLoop();
        }

        private static void RequestLoop()
        {
            while (true)
            {
                //PClient.SendString(client.socket, "Hellllo");
                var msgEnc = PClient.ReceiveResponsePackage(client.socket);
                var msg = PClient.UnPackMessage(msgEnc);
                Console.WriteLine(msg);
                /*
                Console.WriteLine("************************");
                Console.WriteLine($"ClientPublicKey: {Convert.ToBase64String(PClient.PublicKey)}");
                Console.WriteLine($"ServerPublicKey: {Convert.ToBase64String(PClient.ServerPublicKey)}");
                Console.WriteLine($"ServerCert: {Convert.ToBase64String(PClient.ServerCert)}");
                Console.WriteLine($"SecretKey: {Convert.ToBase64String(PClient.SecretKey)}");
                */

                //var x = PClient.PackMessage("oi");

                Console.ReadKey();

                break;
            }
        }

        public static void GenKeys()
        {
            //Generate a public/private key pair.  
            RSA rsa = RSA.Create();

            client = new PClient(rsa.ExportRSAPublicKey(), rsa.ExportRSAPrivateKey());
        }
    }
}

/*  TESTANDO EXPORTAR E IMPORTAR CHAVES
           var rsa = RSA.Create();            
           rsa.ImportRSAPublicKey(client.PublicKey, out _);


           var asr = RSA.Create();
           asr.ImportRSAPrivateKey(client.PrivateKey, out _);


           string textToBeEncrypted = "Hello World";
           byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(textToBeEncrypted);

           byte[] encryptedBytes = rsa.Encrypt(bytesToBeEncrypted, RSAEncryptionPadding.OaepSHA256);

           byte[] decryptedBytes = asr.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
           string result = Encoding.UTF8.GetString(decryptedBytes);

           Console.WriteLine($"Mensagem: {result}");
           */
