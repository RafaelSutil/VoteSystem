using System;
using System.Collections.Generic;
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
        

        static void Main(string[] args)
        {
            Console.WriteLine("Hello Server!");

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

            X509Certificate2 cert = new X509Certificate2(PServer.Certificate);
            var asdewq = cert.GetPublicKey();

            Console.ReadKey();
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

            if(entra == 1)
            {
                string text = Encoding.ASCII.GetString(recBuf);
                Console.WriteLine("Received Text: " + text);
                if (text == "Hello")
                {
                    PServer.Handshake(current);
                }
                current.Send(PServer.PackMessage("1;Eleição Presidente do Corinthians\nInsira Seus dados: "));
                entra = 0;
            }
            else
            {
                var m = PServer.UnPackMessage(recBuf);
                Console.Write("Mensagem descriptografada: ");
                Console.WriteLine(m);
            }



            
            



            
            //var package = text.Split(';');

            /* Tratar as entradas */
            //current.Send(Encoding.ASCII.GetBytes("Server Hello"));

            




            current.BeginReceive(PServer.buffer, 0, PServer.BUFFER_SIZE, SocketFlags.None, ReceiveCallback, current);
        }
    }
}
