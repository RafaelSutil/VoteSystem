using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace VoteProtocol
{
    /// <summary>
    /// Representa uma instância do servidor com métodos e propriedades que auxiliam uma comunicação segura.
    /// </summary>
    public class PServer
    {
        const string SERVER_PUBLICKEY_DIRECTORY = "..\\Certs\\ServerPublicKey.cer";
        const string SERVER_PRIVATEKEY_DIRECTORY = "..\\Certs\\ServerPrivateKey.cer";
        const string SERVER_CERTIFICADO_DIRECTORY = "..\\Certs\\ServerCertificate.cer";

        public static byte[] PublicKey;
        private static byte[] PrivateKey;
        public static byte[] Certificate = new byte[32];

        public static byte[] ClientCert;
        public static byte[] ClientPublicKey = new byte[32];

        private static byte[] SecretKey = new byte[32];

        public const int BUFFER_SIZE = 2048;
        public static byte[] buffer = new byte[BUFFER_SIZE];

        public static int sequenceNumber = 0;

        public static Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        /// <summary>
        /// Inicializa uma nova instância PServer atribuindo os valores das Chaves e do Certificado armazenados localmente.
        /// </summary>
        public PServer()
        {
            PublicKey = Convert.FromBase64String(File.ReadAllText(SERVER_PUBLICKEY_DIRECTORY));
            PrivateKey = Convert.FromBase64String(File.ReadAllText(SERVER_PRIVATEKEY_DIRECTORY));
            Certificate = Convert.FromBase64String(File.ReadAllText(SERVER_CERTIFICADO_DIRECTORY));
        }
        /// <summary>
        /// Realiza a troca de certificados entre cliente e servidor, calcula e envia a chave secreta a fim de gerar o HMAC das mensagens.
        /// </summary>
        /// <param name="current"></param>
        public static void Handshake(Socket current)
        {
            // Enviar Certificado
            current.Send(Certificate);
            // Receber Certificado do Cliente
            ClientCert = ReceiveResponseByte(current);            
            // Extrair Cahve Publica do certificado
            X509Certificate2 cert = new X509Certificate2(ClientCert);
            ClientPublicKey = cert.GetPublicKey();
            // gerar Secret Key
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(SecretKey);
            // Enviar SecretKey criptografado com chave publica do cliente
            using(var rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(ClientPublicKey, out _);
                byte[] encryptedBytes = rsa.Encrypt(SecretKey, RSAEncryptionPadding.OaepSHA256);
                //Console.WriteLine(encryptedBytes.Length);
                current.Send(encryptedBytes);
            }
        }
        /// <summary>
        /// Empacota uma mensagem adicionando o número de sequência, tipo, criptografando e concatenando com o HMAC da mensagem encriptada.
        /// </summary>
        /// <param name="message">String a ser empacotada</param>
        /// <param name="endMessage">Booleano que indica se o pacote é de encerramento de conexão.</param>
        /// <returns>Retorna o pacote pronto para ser transmitido com segurança.</returns>
        public static byte[] PackMessage(string message, bool endMessage)
        {
            byte[] package;
            sequenceNumber++;
            if(endMessage)
                message = sequenceNumber + ";" + "0" + ";" + message;
            else
                message = sequenceNumber + ";" + "1" + ";" + message;
            var EncMsg = Encoding.ASCII.GetBytes(message);
            using (var rsa = RSA.Create())
            using (var hmac = new HMACSHA256(SecretKey))
            {
                rsa.ImportRSAPublicKey(ClientPublicKey, out _);
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
        /// Desempacota a mensagem recebida do cliente, verifica a integridade comparando o HMAC com o gerado localmente, verifica se o número de sequencia é o esperado e o atualiza.
        /// </summary>
        /// <param name="package">Pacote a ser desempacotado.</param>
        /// <returns>Retorna a mensagem descriptografada sem o número de sequencia, sem o tipo e sem o HMAC caso esteja tudo certo, ou retorna a string "ERROR".</returns>
        public string UnPackMessage(byte[] package)
        {
            byte[] encryptedBytes = new byte[256];
            byte[] hashValue = new byte[32];

            for (int i = 0; i < 256; i++)
            {
                encryptedBytes[i] = package[i];
            }
            for (int i = 256; i < 288; i++)
            {
                hashValue[i - 256] = package[i];
            }
            using (var rsa = RSA.Create())
            using (var hmac = new HMACSHA256(SecretKey))
            {
                rsa.ImportRSAPrivateKey(PrivateKey, out _);
                byte[] computedHash = hmac.ComputeHash(encryptedBytes);

                for (int i = 0; i < hashValue.Length; i++)
                {
                    if (hashValue[i] != computedHash[i])
                    {
                        // Console.WriteLine("NAO BATEU COM O HASH");
                        return "ERROR";
                    }
                }
                // Hash verificada
                byte[] EncMsg = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
                string message = Encoding.ASCII.GetString(EncMsg);
                var records = message.Split(';');
                // #seq ; content
                if(int.Parse(records[0]) == sequenceNumber + 1)
                {
                    sequenceNumber++; // atualizar seqnumber
                }
                else
                {
                    //Console.WriteLine("ERRO NO NUMERO DE SEQ");
                    return "ERROR";
                }
                return records[1];
            }
        }
        /// <summary>
        /// Recebe um vetor de Bytes de um Socket conectado.
        /// </summary>
        /// <param name="socket"></param>
        /// <returns>Retorna os bytes recebidos.</returns>
        private static byte[] ReceiveResponseByte(Socket socket)
        {
            var buffer = new byte[2048];
            int received = socket.Receive(buffer, SocketFlags.None);
            if (received == 0) return null;
            var data = new byte[received];
            Array.Copy(buffer, data, received);
            return data;
        }
    }
}
