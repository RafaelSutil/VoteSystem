using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using VoteProtocol;

namespace Server
{
    class Program
    {
        public static PServer server = new PServer();
        private static readonly List<Socket> clientSockets = new List<Socket>();
        public static int entra = 1;

        public static string votingTitle;
        public static string closureDate;
        public static string[] candidates;

        static void Main(string[] args)
        {
            InitialMenu();

            SetupServer();
            Console.ReadKey();
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
            Console.Write("Enter the voting title: ");
            votingTitle = Console.ReadLine();
            Console.WriteLine("Enter the closing date(DD/MM/YY HH:MM):");
            closureDate = Console.ReadLine();
            Console.WriteLine("Do you want to use predefined candidates? Y/N");
            if (Console.ReadLine().ToLower() == "y")
            {
                candidates = File.ReadAllLines(@".\candidates.txt");
            }
            if (Console.ReadLine().ToLower() == "n")
            {
                AddCandidates();
            }

        }

        private static void AddCandidates()
        {
            string input = "";
            int qtd = 0;
            while(true)
            {
                Console.WriteLine("Enter the candidate(ID,Name) or exit:");
                input = Console.ReadLine();
                if (input == "exit")
                    break;
                else
                {
                    candidates[qtd] = input;
                    qtd++;
                }
            }
        }

        private static void SetupServer()
        {
            Console.WriteLine("Setting up server...");
            server.socket.Bind(new IPEndPoint(IPAddress.Any, 100));
            server.socket.Listen(0);
            server.socket.BeginAccept(AcceptCallback, null);
            Console.WriteLine("Server setup complete");
        }

        private static void AcceptCallback(IAsyncResult AR)
        {
            Socket socket;
            try
            {
                socket = server.socket.EndAccept(AR);
            }
            catch (ObjectDisposedException) // I cannot seem to avoid this (on exit when properly closing sockets)
            {
                return;
            }
            clientSockets.Add(socket);
            socket.BeginReceive(PServer.buffer, 0, PServer.BUFFER_SIZE, SocketFlags.None, ReceiveCallback, socket);
            Console.WriteLine("Client connected, waiting for request...");
            server.socket.BeginAccept(AcceptCallback, null);
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
                Console.WriteLine("Client forcefully disconnected");
                // Don't shutdown because the socket may be disposed and its disconnected anyway.
                current.Close();
                clientSockets.Remove(current);
                return;
            }
            byte[] recBuf = new byte[received];
            Array.Copy(PServer.buffer, recBuf, received);

            string m;
            switch (PServer.sequenceNumber)
            {
                case 0: //Receber Hello
                    string text = Encoding.ASCII.GetString(recBuf);
                    //Console.WriteLine("Received Text: " + text);
                    if (text == "Hello")
                    {
                        PServer.Handshake(current);
                        current.Send(PServer.PackMessage("1/Eleição Presidente do Corinthians\nInsira Seus dados: "));
                    }
                    else
                    {
                        Console.WriteLine("Falta de integridade no handshake");
                        current.Shutdown(SocketShutdown.Both);
                        current.Close();
                    }
                    break;
                case 1:
                    m = PServer.UnPackMessage(recBuf);
                    Console.Write("1 - Mensagem descriptografada: ");
                    Console.WriteLine(m);
                    current.Send(PServer.PackMessage("Estamos juntos"));
                    break;
                case 3:
                    m = PServer.UnPackMessage(recBuf);
                    Console.Write("2 - Mensagem descriptografada: ");
                    Console.WriteLine(m);
                    current.Send(PServer.PackMessage("Vai Corinthians"));
                    break;
                case 5:
                    m = PServer.UnPackMessage(recBuf);
                    Console.Write("3 - Mensagem descriptografada: ");
                    Console.WriteLine(m);
                    current.Send(PServer.PackMessage("Bando de loucos"));
                    break;
                case 7:
                    m = PServer.UnPackMessage(recBuf);
                    Console.Write("4 - Mensagem descriptografada: ");
                    Console.WriteLine(m);
                    current.Send(PServer.PackMessage("Pra cima delas"));
                    break;
                case 9:
                    m = PServer.UnPackMessage(recBuf);
                    Console.Write("5 - Mensagem descriptografada: ");
                    Console.WriteLine(m);
                    current.Send(PServer.PackMessage("Nao tem pra ninguem"));
                    break;
                case 11:
                    m = PServer.UnPackMessage(recBuf);
                    Console.Write("5 - Mensagem descriptografada: ");
                    Console.WriteLine(m);
                    current.Send(PServer.PackMessage("Nao para de lutar"));
                    break;
                default:
                    Console.WriteLine("Chegou no default");
                    break;
            }
            //var package = text.Split(';');

            /* Tratar as entradas */
            //current.Send(Encoding.ASCII.GetBytes("Server Hello"));
            try
            {
                current.BeginReceive(PServer.buffer, 0, PServer.BUFFER_SIZE, SocketFlags.None, ReceiveCallback, current);
            }
            catch (Exception)
            {
                Console.WriteLine("Client desconectado!");
            }
            
        }
    }
}
