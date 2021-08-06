using System;
using System.Security.Cryptography;
using System.Text;
using VoteProtocol;

namespace Client
{
    class Program
    {
        public static PClient client = new PClient();
        static void Main(string[] args)
        {
            Console.WriteLine("Hello Client!");

            //Connect
            PClient.ConnectToServer(client.socket);
            //Handshake
            PClient.HandShake(client);
            //While com rcvMsg
            RequestLoop();
        }

        private static void RequestLoop()
        {
            var count = 0;
            while (count != 5)
            {
                //PClient.SendString(client.socket, "Hellllo");
                var msgEnc = PClient.ReceiveResponsePackage(client.socket);
                var msg = PClient.UnPackMessage(msgEnc);
                Console.WriteLine(msg);

                client.socket.Send(PClient.PackMessage("RAFAEL/123"));
                /*
                Console.WriteLine("************************");
                Console.WriteLine($"ClientPublicKey: {Convert.ToBase64String(PClient.PublicKey)}\n");
                Console.WriteLine($"ServerPublicKey: {Convert.ToBase64String(PClient.ServerPublicKey)}\n");
                Console.WriteLine($"ServerCert: {Convert.ToBase64String(PClient.ServerCert)}\n");
                Console.WriteLine($"ClientCert: {Convert.ToBase64String(PClient.Certificate)}\n");
                Console.WriteLine($"SecretKey: {Convert.ToBase64String(PClient.SecretKey)}\n");
                */

                //var x = PClient.PackMessage("oi");

                Console.ReadKey();
                count++;
                //break;
            }
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
