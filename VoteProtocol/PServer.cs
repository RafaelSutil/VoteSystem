﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace VoteProtocol
{
    
    public class PServer
    {
        public byte[] PublicKey;
        public static byte[] PrivateKey;
        public static byte[] SecretKey = new byte[32];
        public static byte[] ClientPublicKey = new byte[32];
        public static byte[] Certificate = new byte[32];

        public const int BUFFER_SIZE = 2048;
        public static byte[] buffer = new byte[BUFFER_SIZE];


        public Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        public PServer(byte[] publicKey, byte[] privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        public static void Handshake(Socket current)
        {
            // Enviar Certificado
            current.Send(Certificate);
            // Receber Chave Publica do Cliente
            ClientPublicKey = ReceiveResponseByte(current);
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

        public static byte[] PackMessage(string message)
        {
            byte[] package;
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

        public static string UnPackMessage(byte[] package)
        {
            byte[] encryptedBytes = new byte[256];
            byte[] hashValue = new byte[32];

            encryptedBytes = package[0..255];
            hashValue = package[256..287];
            using (var rsa = RSA.Create())
            using (var hmac = new HMACSHA256(SecretKey))
            {
                rsa.ImportRSAPrivateKey(PrivateKey, out _);
                byte[] computedHash = hmac.ComputeHash(encryptedBytes);

                for (int i = 0; i < hashValue.Length; i++)
                {
                    if (hashValue[i] != computedHash[i])
                    {
                        Console.WriteLine("NAO BATEU COM O HASH");
                        return "ERRO";
                    }
                }

                // Hash verificada
                byte[] EncMsg = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
                string message = Encoding.ASCII.GetString(EncMsg);
                return message;
            }
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
    }
}