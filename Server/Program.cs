using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using VoteProtocol;

namespace Server
{
    class Program
    {
        public static PServer server = new PServer();
        private static readonly List<Socket> clientSockets = new List<Socket>();

        public static string votingTitle;
        public static int howMuchVotes;
        public static DateTime closureDate;
        public static List<string> alreadyVoted = new List<string>();
        public static List<string> candidates = new List<string>();
        private static int[] votes = new int[50];
        public static string busy = "0";

        public static string cpfClient = "";

        static void Main(string[] args)
        {
            Console.Clear();
            InitialMenu();
            SetupServer();
            /*
            Console.WriteLine("************************");
            Console.WriteLine($"ClientPublicKey: {Convert.ToBase64String(PServer.ClientPublicKey)}\n");
            Console.WriteLine($"ServerPublicKey: {Convert.ToBase64String(PServer.PublicKey)}\n");
            Console.WriteLine($"ServerCert: {Convert.ToBase64String(PServer.Certificate)}\n");
            Console.WriteLine($"ClientCert: {Convert.ToBase64String(PServer.ClientCert)}\n");
            Console.WriteLine($"SecretKey: {Convert.ToBase64String(PServer.SecretKey)}\n");
            */
            Console.ReadKey();
        }

        static void InitialMenu()
        {
            Console.WriteLine("Welcome to Voting System Server!");
            Console.WriteLine("Do you want to add new users? Y/N");
            var opt = Console.ReadLine().ToLower();
            if (opt == "y")
            {
                var Users = File.ReadAllText(@".\Users.txt");
                string input = "";
                while (true)
                {
                    Console.WriteLine("Enter the User(CPF,Password) or exit:");
                    input = Console.ReadLine();
                    if (input == "exit")
                        break;
                    else
                    {
                        var pw = input.Split(',')[1];
                        pw = PServer.CalculateSHA256(pw);

                        input = input.Split(',')[0] + "," + pw;

                        Users += '\n' + input;
                        File.WriteAllText(@".\Users.txt", Users);
                    }
                }
            }

            Console.Write("Enter the voting title: ");
            votingTitle = Console.ReadLine();
            Console.WriteLine("Enter the closing date(MM/DD/YYYY HH:mm:SS):");
            string date = Console.ReadLine();
            closureDate = DateTime.Parse(date);
            Console.WriteLine("What is the maximum number of votes?");
            howMuchVotes = int.Parse(Console.ReadLine());

            Console.WriteLine("Do you want to use predefined candidates? Y/N");
            opt = Console.ReadLine().ToLower();
            if (opt == "y")
            {
                var Vcandidates = File.ReadAllLines(@".\Candidates.txt");
                foreach (var candidate in Vcandidates)
                {
                    candidates.Add(candidate);
                }
            }
            if (opt == "n")
            {
                Console.Clear();
                AddCandidates();
            }
        }
        private static void AddCandidates()
        {
            string input = "";
            while (true)
            {
                Console.WriteLine("Enter the candidate(ID,Name) or exit:");
                input = Console.ReadLine();
                if (input == "exit")
                    break;
                else
                {
                    candidates.Add(input);
                }
            }
        }
        private static void SetupServer()
        {
            Console.WriteLine("Setting up server...");
            PServer.socket.Bind(new IPEndPoint(IPAddress.Any, 100));
            PServer.socket.Listen(0);
            PServer.socket.BeginAccept(AcceptCallback, null);
            Console.Clear();

            Console.WriteLine("Server setup complete");
        }

        public static bool ElectionIsActive()
        {
            if (DateTime.Now < closureDate && howMuchVotes > 0)
            {
                return true;
            }
            return false;
        }

        private static void AcceptCallback(IAsyncResult AR)
        {
            while (busy == "1")
            {
                //Console.WriteLine("Waiting...");
                Thread.Sleep(5000);
            }
            PServer.sequenceNumber = 0;

            Socket socket;
            try
            {
                socket = PServer.socket.EndAccept(AR);
            }
            catch (ObjectDisposedException) // I cannot seem to avoid this (on exit when properly closing sockets)
            {
                return;
            }
            clientSockets.Add(socket);
            socket.BeginReceive(PServer.buffer, 0, PServer.BUFFER_SIZE, SocketFlags.None, ReceiveCallback, socket);
            busy = "1";
            //Console.WriteLine("Client connected, waiting for request...");          

            PServer.socket.BeginAccept(AcceptCallback, null);
        }

        private static void ReceiveCallback(IAsyncResult AR)
        {
            Socket current = (Socket)AR.AsyncState;
            int received;
            try
            {
                received = current.EndReceive(AR);
            }
            catch (SocketException)
            {
                //Console.WriteLine("Client disconnected");
                busy = "0";
                // Don't shutdown because the socket may be disposed and its disconnected anyway.
                current.Close();
                clientSockets.Remove(current);
                return;
            }
            byte[] recBuf = new byte[received];
            Array.Copy(PServer.buffer, recBuf, received);
            string msgReceive;
            string[] datas;

            //Console.WriteLine($"Num de Seq: {PServer.sequenceNumber} ||| msg: {Encoding.ASCII.GetString(recBuf)}");

            if (PServer.sequenceNumber == 0)
            {
                //Receber Hello
                string text = Encoding.ASCII.GetString(recBuf);
                //Console.WriteLine("Received Text: " + text);
                if (text == "Hello")
                {
                    PServer.Handshake(current);
                    current.Send(PServer.PackMessage($"X/{votingTitle}\nEnter your credentials: ", false));
                }
                else
                {
                    //Console.WriteLine("Message without integrity");
                    current.Shutdown(SocketShutdown.Both);
                    current.Close();
                }
            }
            else
            {
                //Console.Write("LENGTH: ");
                //Console.WriteLine(recBuf.Length);
                msgReceive = server.UnPackMessage(recBuf);
                if (msgReceive == "ERROR")
                {
                    current.Send(PServer.PackMessage($"Z/The hash or sequence number did not match", true));
                    current.Shutdown(SocketShutdown.Both);
                    current.Close();
                }
                datas = msgReceive.Split('/');
                X509Certificate2 clientCert;
                switch (datas[0])
                {
                    case "A": //Login
                        // Conferir login no banco de dados
                        var Users = File.ReadAllLines(@".\Users.txt");
                        bool loginSuccess = false;
                        foreach (var user in Users)
                        {
                            if (datas[1] == user)
                            {
                                // Conferir cpf com certificado
                                cpfClient = datas[1].Split(',')[0];
                                clientCert = new X509Certificate2(PServer.ClientCert);
                                if ("CN=" + cpfClient != clientCert.SubjectName.Name)
                                {
                                    //Console.WriteLine("CPF NAO CONFERE COM CERTIFICADO!");
                                    current.Send(PServer.PackMessage($"Z/Your CPF does not match the certificate sent earlier", true));

                                }
                                // Verificar se ja votou
                                if (alreadyVoted.Contains(cpfClient) && ElectionIsActive())
                                {
                                    //Console.WriteLine("ESTE CPF JA VOTOU!");
                                    current.Send(PServer.PackMessage($"Z/Voting is open and you have already voted", true));
                                    break;
                                }
                                //verificar se eleicao ta ativa
                                if (ElectionIsActive())
                                {
                                    //ativa - envia candidatos
                                    //Console.WriteLine("Election is Active");
                                    string stringCandidates = "";
                                    foreach (var candidate in candidates)
                                    {
                                        stringCandidates += candidate + "\n";
                                    }
                                    current.Send(PServer.PackMessage("Y/Candidates:\n" + stringCandidates, false));
                                }
                                else
                                {
                                    //Console.WriteLine("Election is over");
                                    //encerrada - envia resultados
                                    int j = 1;
                                    string result = "";
                                    foreach (var x in candidates)
                                    {
                                        result += $"{x}: {votes[j]}\n";
                                        j++;
                                    }
                                    busy = "0";
                                    current.Send(PServer.PackMessage($"Z/The Vote Is Over\n############### RESULT ###############\n{result}", true));
                                }
                                loginSuccess = true;
                                break;
                            }
                        }
                        if (!loginSuccess)
                        {
                            current.Send(PServer.PackMessage($"X/Incorrect password!\nEnter your credentials again: ", false));
                        }
                        break;
                    case "B":
                        howMuchVotes--;
                        //Recebe voto
                        votes[int.Parse(datas[1])]++;
                        // Contabiliza voto
                        alreadyVoted.Add(cpfClient);
                        // Manda msg de finalizacao com tipo 0
                        int i = 1;
                        Console.Clear();
                        Console.WriteLine("############### RESULT ###############");
                        foreach (var x in candidates)
                        {
                            Console.WriteLine($"{x}: {votes[i]}");
                            i++;
                        }
                        Console.WriteLine("############### CPFs ###############");
                        foreach (var x in alreadyVoted)
                        {
                            Console.WriteLine(x);
                        }
                        //Console.WriteLine("##############################");
                        current.Send(PServer.PackMessage($"Z/Thank you for voting", true));
                        break;
                    default:
                        //Console.WriteLine("default");
                        break;
                }
            }
            try
            {
                current.BeginReceive(PServer.buffer, 0, PServer.BUFFER_SIZE, SocketFlags.None, ReceiveCallback, current);
            }
            catch (Exception)
            {
                //Console.WriteLine("Client disconnected!");
                busy = "0";
            }

        }
    }
}
