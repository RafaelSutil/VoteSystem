using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace VoteProtocol
{
    public class PClient
    {
        public static byte[] PublicKey = new byte[32];
        public static byte[] PrivateKey;
        public static byte[] Certificate;

        public static byte[] ServerCert;
        public static byte[] ServerPublicKey;

        public static byte[] SecretKey = new byte[32];

        public Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        public PClient()
        {
            PublicKey = Convert.FromBase64String(File.ReadAllText("..\\Certs\\ClientPublicKey.cer"));
            PrivateKey = Convert.FromBase64String(File.ReadAllText("..\\Certs\\ClientPrivateKey.cer"));
            Certificate = Convert.FromBase64String(File.ReadAllText("..\\Certs\\ClientCertificate.cer"));
        }

        public static void HandShake(PClient client)
        {
            // Enviar Hello
            SendString(client.socket, "Hello");
            // Receber Certificado
            ServerCert = ReceiveResponseByte(client.socket);
            // Validar Certificado
            // Extrair Chave Publica do Certificado
            X509Certificate2 cert = new X509Certificate2(ServerCert);
            ServerPublicKey = cert.GetPublicKey();

            // Enviar Chave Publica
            client.socket.Send(Certificate);
            // Receber Kc+(SecretKey)
            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(PrivateKey, out _);
                SecretKey = rsa.Decrypt(ReceiveResponseKey(client.socket), RSAEncryptionPadding.OaepSHA256);
            }
        }
        public static void ConnectToServer(Socket ClientSocket)
        {
            int attempts = 0;
            while (!ClientSocket.Connected)
            {
                try
                {
                    attempts++;
                    Console.WriteLine("Connection attempt " + attempts);
                    // Change IPAddress.Loopback to a remote IP to connect to a remote host.
                    ClientSocket.Connect(IPAddress.Loopback, 100);
                }
                catch (SocketException)
                {
                    //Console.Clear();
                }
            }
            //Console.Clear();
            Console.WriteLine("Connected");
        }

        public static void SendString(Socket socket, string text)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(text);
            socket.Send(buffer, 0, buffer.Length, SocketFlags.None);
        }
        public static string ReceiveResponseString(Socket socket)
        {
            var buffer = new byte[2048];
            int received = socket.Receive(buffer, SocketFlags.None);
            if (received == 0) return "ERRO";
            var data = new byte[received];
            Array.Copy(buffer, data, received);
            string text = Encoding.ASCII.GetString(data);
            return text;
        }
        public static byte[] ReceiveResponseByte(Socket socket)
        {
            var buffer = new byte[2048];
            int received = socket.Receive(buffer, SocketFlags.None);
            if (received == 0) return null;
            var data = new byte[received];
            Array.Copy(buffer, data, received);
            return data;
        }

        public static byte[] ReceiveResponseKey(Socket socket)
        {
            var buffer = new byte[256];
            int received = socket.Receive(buffer, SocketFlags.None);
            if (received == 0) return null;
            var data = new byte[received];
            Array.Copy(buffer, data, received);
            return data;
        }

        public static byte[] ReceiveResponsePackage(Socket socket)
        {
            var buffer = new byte[288];
            int received = socket.Receive(buffer, SocketFlags.None);
            if (received == 0) return null;
            var data = new byte[received];
            Array.Copy(buffer, data, received);
            return data;
        }

        public static byte[] PackMessage(string message)
        {
            byte[] package;
            var EncMsg = Encoding.ASCII.GetBytes(message);
            using(var rsa = RSA.Create())
            using(var hmac = new HMACSHA256(SecretKey))
            {
                rsa.ImportRSAPublicKey(ServerPublicKey, out _); //Criptografa com chave do servidor
                byte[] encryptedBytes = rsa.Encrypt(EncMsg, RSAEncryptionPadding.OaepSHA256);//256
                byte[] hashValue = hmac.ComputeHash(encryptedBytes);//32
                int length = encryptedBytes.Length + hashValue.Length;
                package = new byte[length];
                encryptedBytes.CopyTo(package, 0);
                hashValue.CopyTo(package, encryptedBytes.Length);
            }

            return package;
        }
        public static string UnPackMessage(byte[] package)
        {
            byte[] encryptedBytes = new byte[256];
            byte[] hashValue = new byte[32];

            //encryptedBytes = package[0..255];
            for(int i=0; i<256; i++)
            {
                encryptedBytes[i] = package[i];
            }
            for (int i = 256; i < 288; i++)
            {
                hashValue[i-256] = package[i];
            }
            //hashValue = package[256..287];


            using (var rsa = RSA.Create())
            using(var hmac = new HMACSHA256(SecretKey))
            {
                rsa.ImportRSAPrivateKey(PrivateKey, out _); //descriptografa com chave do cliente
                byte[] computedHash = hmac.ComputeHash(encryptedBytes);

                for(int i=0; i<hashValue.Length; i++)
                {
                    if(hashValue[i] != computedHash[i])
                    {
                        Console.WriteLine("NAO BATEU COM O HASH PCLIENT");
                        return "ERRO";
                    }
                }

                // Hash verificada
                byte[] EncMsg = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
                string message = Encoding.ASCII.GetString(EncMsg);
                return message;
            }


            /*

            byte[] encryptedBytes;
            var EncMsg = Encoding.ASCII.GetBytes(message);
            using (var rsa = RSA.Create())
            using (var hmac = new HMACSHA256(SecretKey))
            {
                rsa.ImportRSAPublicKey(PublicKey, out _);
                encryptedBytes = rsa.Encrypt(EncMsg, RSAEncryptionPadding.OaepSHA256);
                byte[] hashValue = hmac.ComputeHash(encryptedBytes);

                encryptedBytes.Concat(hashValue);
            }

            return encryptedBytes;*/
        }
    }

}
