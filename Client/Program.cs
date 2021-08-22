using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Timers;
using VoteProtocol;


namespace Client
{
    class Program
    {
        public static PClient client = new PClient();
        private static System.Timers.Timer aTimer;
        static void Main(string[] args)
        {
            Console.Clear();
            // Connect
            ConnectToServer();
            // Handshake
            client.HandShake();

            SetTimer();

            // While com rcvMsg
            RequestLoop();
        }
        private static void SetTimer()
        {
            // Create a timer with a 60 seconds interval.
            aTimer = new Timer(60000);
            // Hook up the Elapsed event for the timer. 
            aTimer.Elapsed += OnTimedEvent;
            aTimer.AutoReset = true;
            aTimer.Enabled = true;
        }
        private static void OnTimedEvent(Object source, ElapsedEventArgs e)
        {
            Console.Clear();
            Console.WriteLine("You have been disconnected for timing out.");
            Environment.Exit(0);
        }

        public static void ConnectToServer()
        {
            int attempts = 0;
            while (!client.socket.Connected)
            {
                try
                {
                    attempts++;
                    Console.WriteLine("Welcome to Voting System Client!");

                    Console.WriteLine("Connection attempt " + attempts);
                    // Change IPAddress.Loopback to a remote IP to connect to a remote host.
                    client.socket.Connect(IPAddress.Loopback, 100);
                }
                catch (SocketException)
                {
                    Console.Clear();
                }
            }
            //Console.Clear();
            Console.WriteLine("You are in the queue. Wait your turn!");
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
                var msgEnc = client.ReceiveResponsePackage();
                var msg = client.UnPackMessage(msgEnc);
                datas = msg.Split('/');
                switch (datas[0])
                {
                    case "X": //Login
                        Console.Clear();
                        Console.WriteLine(datas[1]);
                        Console.Write("CPF: ");
                        cpf = Console.ReadLine();
                        Console.Write("Password: ");
                        password = Console.ReadLine();
                        password = client.CalculateSHA256(password);
                        client.socket.Send(client.PackMessage("A/" + cpf + "," + password));
                        break;

                    case "Y": //Vote
                        Console.Clear();
                        Console.WriteLine(datas[1]);

                        var voteSuccess = false;
                        while (voteSuccess == false)
                        {
                            Console.Write("Enter the candidate ID: ");
                            var candidateId = Console.ReadLine();
                            var ids = datas[1].Split('\n');
                            foreach (var id in ids)
                            {
                                if (candidateId.Equals(id.Split(',')[0]))
                                {
                                    //vote
                                    client.socket.Send(client.PackMessage("B/" + candidateId));
                                    voteSuccess = true;
                                    break;
                                }
                            }
                        }
                        break;

                    case "Z":
                        Console.Clear();
                        if (datas[2] == "EndMessage")
                        {
                            Console.WriteLine(datas[1]);
                            finished = true;
                        }
                        else
                        {
                            Console.WriteLine("It's not a EndMessage! Truncation Attack!");
                        }
                        break;

                    default:
                        client.socket.Send(client.PackMessage("Default/123"));
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
