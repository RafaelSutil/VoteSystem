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
            string[] datas;
            string cpf;
            string password;
            bool finished = false;
            while (!finished)
            {
                //PClient.SendString(client.socket, "Hellllo");
                var msgEnc = PClient.ReceiveResponsePackage(client.socket);
                var msg = PClient.UnPackMessage(msgEnc);
                //Console.WriteLine(msg);

                datas = msg.Split('/');
                switch (datas[0])
                {
                    case "X": //Login
                        Console.WriteLine(datas[1]);
                        Console.Write("CPF: ");
                        cpf = Console.ReadLine();
                        Console.Write("Password: ");
                        password = Console.ReadLine();
                        password = PClient.CalculateSHA256(password);
                        client.socket.Send(PClient.PackMessage("A/" + cpf + "," + password));
                        break;

                    case "Y": //Vote
                        Console.WriteLine(datas[1]);

                        var voteSuccess = false;
                        while (voteSuccess == false)
                        {
                            Console.Write("Enter the candidate ID: ");
                            var candidateId = Console.ReadLine();
                            var ids = datas[1].Split('\n');
                            foreach (var id in ids)
                            {/*
                                Console.WriteLine("-------" + id.Split(',')[0] + "---------" + candidateId + "-------");
                                Console.WriteLine(candidateId.Equals(id.Split(',')[0]));
                                Console.WriteLine("\n\n");*/
                                if (candidateId.Equals(id.Split(',')[0]))
                                {
                                    //vote
                                    client.socket.Send(PClient.PackMessage("B/"+ candidateId));
                                    voteSuccess = true;

                                    break;
                                }
                            }
                        }     
                        break;

                    case "Z":
                        if(datas[2] == "EndMessage")
                        {
                            Console.WriteLine(datas[1]);
                            finished = true;
                        }
                        else
                        {
                            Console.WriteLine("NAO EH UMA MENSAGEM DE ENCERRAMENTO");
                        }
                        break;

                    default:
                        client.socket.Send(PClient.PackMessage("Default/123"));
                        break;
                }

                /*
                Console.WriteLine("************************");
                Console.WriteLine($"ClientPublicKey: {Convert.ToBase64String(PClient.PublicKey)}\n");
                Console.WriteLine($"ServerPublicKey: {Convert.ToBase64String(PClient.ServerPublicKey)}\n");
                Console.WriteLine($"ServerCert: {Convert.ToBase64String(PClient.ServerCert)}\n");
                Console.WriteLine($"ClientCert: {Convert.ToBase64String(PClient.Certificate)}\n");
                Console.WriteLine($"SecretKey: {Convert.ToBase64String(PClient.SecretKey)}\n");
                */

                //var x = PClient.PackMessage("oi");

                //Console.ReadKey();
                count++;
                //break;
            }
            Console.ReadKey();
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
