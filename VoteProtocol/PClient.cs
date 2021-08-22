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
                ServerCert = ReceiveResponseBytes();
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
                    // Importa chave privada do Cliente em rsa
                    rsa.ImportRSAPrivateKey(PrivateKey, out _);
                    // Descriptografa a mensagem recebida para ter a SecretKey
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
            // Verifica se o certificado é nulo
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
            // Verifica se o emissor do certificado bate com o ElectionServer
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
        public byte[] ReceiveResponseBytes()
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
        /// Empacota uma mensagem adicionando o número de sequência e um número randômico, criptografando e concatenando com o HMAC da mensagem criptografada.
        /// </summary>
        /// <param name="message">String a ser empacotada.</param>
        /// <returns>Retorna o pacote pronto para ser transmitido com segurança.</returns>
        public byte[] PackMessage(string message)
        {
            byte[] package;
            sequenceNumber++;
            var rdn = new Random();
            // Adiciona na mensagem o numero de sequencia e um número randômico
            message = sequenceNumber + ";" + message + ";" + rdn.Next();
            // Codifica a mensagem em bytes
            var EncMsg = Encoding.ASCII.GetBytes(message);
            using (var rsa = RSA.Create())
            using (var hmac = new HMACSHA256(SecretKey)) // Importa a SecretKey em hmac
            {
                // Importa Chave publica do servidor em rsa
                rsa.ImportRSAPublicKey(ServerPublicKey, out _);
                // Criptografa a mensagem usando rsa
                byte[] encryptedBytes = rsa.Encrypt(EncMsg, RSAEncryptionPadding.OaepSHA256);//256
                // Calcula o HMAC da mensagem criptografada usando o SecretKey
                byte[] hashValue = hmac.ComputeHash(encryptedBytes);//32
                package = new byte[288];
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
            // Extrai a mensagem do pacote
            for (int i = 0; i < 256; i++)
            {
                encryptedBytes[i] = package[i];
            }
            // Extrai o HMAC da mensagem
            for (int i = 256; i < 288; i++)
            {
                hashValue[i - 256] = package[i];
            }
            using (var rsa = RSA.Create())
            using (var hmac = new HMACSHA256(SecretKey)) // Importa SecretKey em hmac
            {
                // Importa a chave privada do cliente em rsa
                rsa.ImportRSAPrivateKey(PrivateKey, out _);
                // Calcula o valor de HMAC da mensagem criptografada
                byte[] computedHash = hmac.ComputeHash(encryptedBytes);
                // Compara byte a byte o valor de HMAC que acabamos de calcular com o extraido do pacote
                for (int i = 0; i < hashValue.Length; i++)
                {
                    if (hashValue[i] != computedHash[i])
                    {
                        throw new ArgumentException("Message without integrity");
                    }
                }
                // Descriptografa a mensagem extraida do pacote
                byte[] EncMsg = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
                // Decodifica de byte para string
                string message = Encoding.ASCII.GetString(EncMsg);
                // Separa a mensagem em records (#SEQ / Type / Content)
                var records = message.Split(';');
                // Verifica se o numero de sequencia é o esperado
                if (int.Parse(records[0]) == sequenceNumber + 1)
                {
                    sequenceNumber++; // atualizar seqnumber
                }
                else
                {
                    throw new Exception("Sequence number does not match");
                }
                // Verifica se o tipo da mensagem é de encerramento
                if (records[1] == "0")
                    // Adiciona a tag para o cliente saber que o servidor enviou uma msg de encerramento
                    return records[2] + "/EndMessage";
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
