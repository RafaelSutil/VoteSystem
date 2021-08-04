using System;

namespace Scripts
{
    class Program
    {
        static void Main(string[] args)
        {
            GenServerCert.GenCertsKeys();
            GenClientKey.GenCertsKeys();
            Console.WriteLine("Chaves e Certificados gerados");
        }
    }
}
