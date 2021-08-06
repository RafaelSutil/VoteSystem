using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace VoteProtocol
{
    /// <summary>
    /// Representa uma instância de Client com métodos e propriedades que auxiliam uma comunicação segura entre cliente e servidor.
    /// </summary>
    public class PClient
    {
        public static byte[] PublicKey = new byte[32];
        public static byte[] PrivateKey;
        public static byte[] Certificate;

        public static byte[] ServerCert;
        public static byte[] ServerPublicKey;

        public static byte[] SecretKey = new byte[32];

        public static int sequenceNumber = 0;

        public Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        /// <summary>
        /// Inicializa uma nova instância PClient atribuindo os valores das Chaves e do Certificado armazenados localmente.
        /// </summary>
        public PClient()
        {
            PublicKey = Convert.FromBase64String(File.ReadAllText("..\\Certs\\ClientPublicKey.cer"));
            PrivateKey = Convert.FromBase64String(File.ReadAllText("..\\Certs\\ClientPrivateKey.cer"));
            Certificate = Convert.FromBase64String(File.ReadAllText("..\\Certs\\ClientCertificate.cer"));
        }

        public static void HandShake(PClient client)
        {
            try
            {
                // Enviar Hello
                SendString(client.socket, "Hello");
                // Receber Certificado
                ServerCert = ReceiveResponseByte(client.socket);
                // Validar Certificado
                X509Certificate2 cert = new X509Certificate2(ServerCert);
                CertValidate(cert);

                // Extrair Chave Publica do Certificado
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
            catch (Exception)
            {
                Console.WriteLine("FALTA DE INTEGRIDADE NO HANDSHAKE");
                Environment.Exit(123);
            }
        }

        public static void CertValidate(X509Certificate2 certificate)
        {
            // Check that there is a certificate.
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }

            // Check that the certificate issuer matches the configured issuer
            if ("CN=ElectionServer" != certificate.IssuerName.Name)
            {
                throw new Exception
                  ("Certificate was not issued by a trusted issuer");
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

            sequenceNumber++;
            message = sequenceNumber + ";" + message;

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

            for(int i=0; i<256; i++)
            {
                encryptedBytes[i] = package[i];
            }
            for (int i = 256; i < 288; i++)
            {
                hashValue[i-256] = package[i];
            }
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

                var records = message.Split(';');

                if (int.Parse(records[0]) == sequenceNumber + 1)
                {
                    sequenceNumber++; // atualizar seqnumber
                }
                else
                {
                    Console.WriteLine("ERRO NO NUMERO DE SEQ");
                }
                if (records[1] == "0")
                    return records[2]+"/EndMessage";
                else
                    return records[2];

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
        public static String CalculateSHA256(String value)
        {
            StringBuilder Sb = new StringBuilder();
            using (SHA256 hash = SHA256Managed.Create())
            {
                Encoding enc = Encoding.UTF8;
                Byte[] result = hash.ComputeHash(enc.GetBytes(value));
                foreach (Byte b in result)
                    Sb.Append(b.ToString("x2"));
            }
            return Sb.ToString();
        }
    }

}
