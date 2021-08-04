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
        public static PServer server;
        private static readonly List<Socket> clientSockets = new List<Socket>();
        

        static void Main(string[] args)
        {
            Console.WriteLine("Hello Server!");
            GenCertsKeys();

            SetupServer();
            Console.ReadKey();
            /*
            Console.WriteLine("************************");
            Console.WriteLine($"ClientPublicKey: {Convert.ToBase64String(PServer.ClientPublicKey)}");
            Console.WriteLine($"ServerPublicKey: {Convert.ToBase64String(server.PublicKey)}");
            Console.WriteLine($"ServerCert: {Convert.ToBase64String(PServer.Certificate)}");
            Console.WriteLine($"SecretKey: {Convert.ToBase64String(PServer.SecretKey)}");
            */

            

            Console.ReadKey();
        }

        public static void GenCertsKeys()
        {
            //Generate a public/private key pair.  
            RSA rsa = RSA.Create();
            server = new PServer(rsa.ExportRSAPublicKey(), rsa.ExportRSAPrivateKey());

            CertificateRequest req = new CertificateRequest($"CN=ElectionServer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
            PServer.Certificate = cert.Export(X509ContentType.Cert);
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

            string text = Encoding.ASCII.GetString(recBuf);
            //Console.WriteLine("Received Text: " + text);

            if(text == "Hello")
            {
                PServer.Handshake(current);
            }
            //var package = text.Split(';');

            /* Tratar as entradas */
            //current.Send(Encoding.ASCII.GetBytes("Server Hello"));

            current.Send(PServer.PackMessage("1;Eleição Presidente do Corinthians\nInsira Seus dados: "));




            current.BeginReceive(PServer.buffer, 0, PServer.BUFFER_SIZE, SocketFlags.None, ReceiveCallback, current);
        }
    }
}
