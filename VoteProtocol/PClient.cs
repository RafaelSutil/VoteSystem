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
    /// Representa uma instância do cliente com métodos e propriedades que auxiliam uma comunicação segura entre cliente e servidor.
    /// </summary>
    public class PClient
    {
        const string CLIENT_PUBLICKEY_DIRECTORY = "..\\Certs\\ClientPublicKey.cer";
        const string CLIENT_PRIVATEKEY_DIRECTORY = "..\\Certs\\ClientPrivateKey.cer";
        const string CLIENT_CERTIFICATE_DIRECTORY = "..\\Certs\\ClientCertificate.cer";

        public static byte[] PublicKey = new byte[32];
        private static byte[] PrivateKey;
        public static byte[] Certificate;

        public static byte[] ServerCert;
        public static byte[] ServerPublicKey;

        private static byte[] SecretKey = new byte[32];

        private static int sequenceNumber = 0;

        public Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        /// <summary>
        /// Inicializa uma nova instância PClient atribuindo os valores das Chaves e do Certificado armazenados localmente.
        /// </summary>
        public PClient()
        {
            PublicKey = Convert.FromBase64String(File.ReadAllText(CLIENT_PUBLICKEY_DIRECTORY));
            PrivateKey = Convert.FromBase64String(File.ReadAllText(CLIENT_PRIVATEKEY_DIRECTORY));
            Certificate = Convert.FromBase64String(File.ReadAllText(CLIENT_CERTIFICATE_DIRECTORY));
        }
        /// <summary>
        /// Realiza a troca de certificados entre cliente e servidor e recebe a chave secreta a fim de gerar o HMAC das mensagens.
        /// </summary>
        /// <exception cref="Exception">Exceção é lançada e o cliente é finalizado quando ocorre um erro em alguma etapa do handshake.</exception>
        public void HandShake()
        {
            try
            {
                // Enviar Hello
                SendString("Hello");
                // Receber Certificado
                ServerCert = ReceiveResponseByte();
                // Validar Certificado
                X509Certificate2 cert = new X509Certificate2(ServerCert);
                CertValidate(cert);
                // Extrair Chave Publica do Certificado
                ServerPublicKey = cert.GetPublicKey();
                // Enviar Chave Publica
                socket.Send(Certificate);
                // Receber Kc+(SecretKey)
                using (var rsa = RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(PrivateKey, out _);
                    SecretKey = rsa.Decrypt(ReceiveResponseKey(), RSAEncryptionPadding.OaepSHA256);
                }
            }
            catch (Exception)
            {
                throw new Exception("Handshake Error");
            }
        }
        /// <summary>
        /// Checa se o certificado recebido do servidor é válido.
        /// </summary>
        /// <param name="certificate">Certificado recebido do servidor.</param>
        /// <exception cref="ArgumentNullException">Exceção é lançada quando o certificado é nulo</exception>
        /// <exception cref="Exception">Exceção é lançada quando o certificado não é do Servidor</exception>
        private static void CertValidate(X509Certificate2 certificate)
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
        /// <summary>
        /// Envia uma string de dados para um Socket conectado.
        /// </summary>
        /// <param name="text">String a ser enviada</param>
        private void SendString(string text)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(text);
            socket.Send(buffer, 0, buffer.Length, SocketFlags.None);
        }
        /// <summary>
        /// Recebe um vetor de Bytes de um Socket conectado.
        /// </summary>
        /// <returns>Retorna os bytes recebidos.</returns>
        private byte[] ReceiveResponseByte()
        {
            var buffer = new byte[2048];
            int received = socket.Receive(buffer, SocketFlags.None);
            if (received == 0) return null;
            var data = new byte[received];
            Array.Copy(buffer, data, received);
            return data;
        }
        /// <summary>
        /// Recebe um vetor de bytes que representa a chave secreta enviada do servidor conectado.
        /// </summary>
        /// <returns>Retorna a chave secreta.</returns>
        private byte[] ReceiveResponseKey()
        {
            var buffer = new byte[256];
            int received = socket.Receive(buffer, SocketFlags.None);
            if (received == 0) return null;
            var data = new byte[received];
            Array.Copy(buffer, data, received);
            return data;
        }
        /// <summary>
        /// Recebe um vetor de bytes que representa um pacote que foi enviado pelo servidor.
        /// </summary>
        /// <returns>Retorna o pacote recebido.</returns>
        public byte[] ReceiveResponsePackage()
        {
            var buffer = new byte[288];
            int received = socket.Receive(buffer, SocketFlags.None);
            if (received == 0) return null;
            var data = new byte[received];
            Array.Copy(buffer, data, received);
            return data;
        }
        /// <summary>
        /// Empacota uma mensagem adicionando o número de sequência, criptografando e concatenando com o HMAC da mensagem encriptada.
        /// </summary>
        /// <param name="message">String a ser empacotada.</param>
        /// <returns>Retorna o pacote pronto para ser transmitido com segurança.</returns>
        public byte[] PackMessage(string message)
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
        /// <summary>
        /// Desempacota a mensagem recebida do servidor, verifica a integridade comparando o HMAC com o gerado localmente, verifica se o número de sequencia é o esperado e o atualiza.
        /// </summary>
        /// <param name="package">Pacote a ser desempacotado.</param>
        /// <returns>Retorna a mensagem descriptografada sem o número de sequencia, sem o tipo e sem o HMAC.</returns>
        /// <exception cref="ArgumentException">Exceção é lançada quando o HMAC não bate com o calculado localmente.</exception>
        /// <exception cref="Exception">Exceção é lançada quando o número de sequencia não é o esperado.</exception>
        public string UnPackMessage(byte[] package)
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
                        throw new ArgumentException("Message without integrity");
                    }
                }
                // Hash verificada
                byte[] EncMsg = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
                string message = Encoding.ASCII.GetString(EncMsg);
                var records = message.Split(';');
                // #seq ; type ; content
                if (int.Parse(records[0]) == sequenceNumber + 1)
                {
                    sequenceNumber++; // atualizar seqnumber
                }
                else
                {
                    throw new Exception("Sequence number does not match");
                }
                if (records[1] == "0")
                    return records[2]+"/EndMessage";
                else
                    return records[2];
            }
        }
        /// <summary>
        /// Calcula o valor SHA256 de uma dada string.
        /// </summary>
        /// <param name="value">String a ser convertida</param>
        /// <returns>Retorna a string do valor calculado.</returns>
        public String CalculateSHA256(String value)
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
