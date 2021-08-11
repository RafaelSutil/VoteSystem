# Protocolo para sistema de votação

Esta biblioteca foi desenvolvida na disciplina de Protocolos de Comunicação do Centro de Informática - UFPE, a fim de manter uma comunicação segura em um sistema de votação, garantindo a **Integridade**, **Confidencialidade** e **Autenticidade**.

### Requisitos

A biblioteca foi desenvolvida na linguagem de programação C# utilizando o framework .NET da Microsoft.

Apesar de ser multiplataforma é recomendado que seja implementado no sistema operacional Windows 10.

### Como funciona?

O protocolo implementado garante a segurança, mas como?

Foi dado que o invasor poderá capturar, ler e injetar pacotes na rede, além de se passar por qualquer IP com a intenção de fraudar a votação ou quebrar o sigilo do voto.

Para garantirmos a confidencialidade da mensagem (o voto) basta criptografarmos a mensagem, que o invasor será impossibilitado de ler, para isso, sempre usaremos a chave pública do destinatário. Vale ressaltar que o invasor também tem acesso às chaves públicas de todos os atores da comunicação, então poderia tentar decifrar a mensagem por tentativa e erro criptografando possíveis mensagens de voto, isso não acontece nesta biblioteca pois a mensagem enviada possui um campo único (nonce).

Outro campo importante para estar no pacote a ser enviado é o HMAC, com ele conseguimos garantir a integridade pois vamos gerar outro HMAC no receptor para verificar se é o mesmo que foi enviado junto a mensagem, e também podemos garantir a autenticidade pois no handshake é atribuído uma chave secreta única para cada cliente, e esta chave é usada para calcular o HMAC. O login só será feito após termos uma conexão segura, o CPF do login deve ser o mesmo CPF do certificado enviado anteriormente no handshake.

Beleza, como o HMAC é único por sessão, não poderemos fazer um ataque de replay, correto? Sim, mas e se eu tentar fazer o ataque em uma mesma sessão? Bem, para isso adicionamos o número de sequência na mensagem, e se o número de sequência enviado não for o esperado, acarretará em uma exceção e o cliente será desconectado.

### Como usar?

São disponibilizados duas classes uma para ser implementado com o servidor (PServer) e outra para ser implementada com o cliente (PClient).

#### PServer

- Propriedades:
  - 
- Métodos:
  - y

#### PClient

****



