using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Packet;

namespace Server
{
    class Server
    {
        TcpListener listener;
        private string ip;
        private int port;
        private List<Client> clientOnServer = new List<Client>();

        private Encryption serverEncryption = new Encryption();
        private string serverPrivateKeyPath = Directory.GetCurrentDirectory() + "\\Server Private Key.txt";
        private string serverPublicKeyPath = Directory.GetCurrentDirectory() + "\\Server Public Key.txt";

        public Server(string _ip, int _port)
        {
            ip = _ip;
            port = _port;

            LoadServerKey();
        }

        public void LoadServerKey()
        {
            if (File.Exists(serverPublicKeyPath) && File.Exists(serverPrivateKeyPath))
            {

                string privateKeyLoaded = File.ReadAllText(serverPrivateKeyPath);
                serverEncryption.privateKey = serverEncryption.ConvertStringToKey(privateKeyLoaded);

                string publicKeyLoaded = File.ReadAllText(serverPublicKeyPath);
                serverEncryption.publicKey = serverEncryption.ConvertStringToKey(publicKeyLoaded);
            }
            else
            {

                serverEncryption.GenerateKey();


                File.WriteAllText(serverPrivateKeyPath, serverEncryption.ConvertKeyToString(serverEncryption.privateKey));
                File.WriteAllText(serverPublicKeyPath, serverEncryption.ConvertKeyToString(serverEncryption.publicKey));
            }


        }

        public void Start()
        {
            listener = new TcpListener(IPAddress.Parse(ip), port);
            listener.Start();
            Console.WriteLine("Server Started");
            listener.BeginAcceptTcpClient(ConnectionCallback, null);
        }

        private void ConnectionCallback(IAsyncResult _result)
        {
            TcpClient client = listener.EndAcceptTcpClient(_result);
            Console.WriteLine($"New Connection From {client.Client.RemoteEndPoint}...");
            listener.BeginAcceptTcpClient(ConnectionCallback, null);


            Client newPlayer = new Client(client, serverEncryption);
            clientOnServer.Add(newPlayer);
        }

    }

    public class Client
    {
        private TcpClient socket;
        private NetworkStream stream;
        private Encryption clientEncryption = new Encryption();
        private Encryption serverEncryption = new Encryption();
        private AesEncryptor symmetricEncryptor = new AesEncryptor();

        public Client(TcpClient _client, Encryption serverEncryption)
        {
            this.serverEncryption = serverEncryption;

            socket = _client;
            socket.ReceiveBufferSize = Constant.dataBuffer.Length;
            socket.SendBufferSize = Constant.dataBuffer.Length;

            stream = socket.GetStream();

            stream.BeginRead(Constant.dataBuffer, 0, Constant.dataBuffer.Length, ReceiveData, null);
        }

        private void ReceiveData(IAsyncResult _result)
        {
            try
            {
                int _byteLength = stream.EndRead(_result);
                if (_byteLength <= 0)
                {

                    return;
                }

                byte[] data = new byte[_byteLength];
                Array.Copy(Constant.dataBuffer, data, _byteLength);

                HandleData(data);
                stream.BeginRead(Constant.dataBuffer, 0, Constant.dataBuffer.Length, ReceiveData, null);
            }
            catch (Exception _ex)
            {
                Console.WriteLine($"Client Disconnected");


                socket.Close();
            }
        }

        private void HandleData(byte[] data)
        {
            byte[] buffer = data;
            int readPos = 0;


            int packetType = BitConverter.ToInt32(buffer, readPos);
            readPos += 4;


            byte[] messageData = new byte[buffer.Length - 4];
            Array.Copy(buffer, readPos, messageData, 0, buffer.Length - readPos);

            switch (packetType)
            {
                case (int)Packet.Packet.SEND_KEY:

                    string keyString = Encoding.ASCII.GetString(messageData);

                    string decrypted = serverEncryption.Decrypt(keyString);
                    Console.WriteLine($"Received Client Public Key..");

                    clientEncryption.publicKey = serverEncryption.ConvertStringToKey(decrypted);
                    SendSymmetricKey();
                    break;
                case (int)Packet.Packet.SEND_MESSAGE:
                    try
                    {
                        string message = Encoding.ASCII.GetString(messageData, 0, messageData.Length);
                        string decryptedMsg = symmetricEncryptor.Decrypt(message);
                        Console.WriteLine($"Message from Client: {decryptedMsg}");
                        SendMessage("Hello!");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error: {e.InnerException}");
                    }
                    break;
                default:
                    break;
            }
        }

        public void SendData(Packet.Packet packet, string data)
        {

            List<byte> dataToSend = new List<byte>();
            dataToSend.AddRange(BitConverter.GetBytes((int)packet));
            dataToSend.AddRange(Encoding.ASCII.GetBytes(data));


            stream.Write(dataToSend.ToArray(), 0, dataToSend.Count);
        }

        public void SendData(Packet.Packet packet, byte[] data)
        {
            List<byte> dataToSend = new List<byte>();
            dataToSend.AddRange(BitConverter.GetBytes((int)packet));
            dataToSend.AddRange(data);


            stream.Write(dataToSend.ToArray(), 0, dataToSend.Count);
        }

        public void SendMessage(string msg)
        {
            string encryptedWithSymKey = symmetricEncryptor.Encrypt(msg);
            SendData(Packet.Packet.SEND_MESSAGE, encryptedWithSymKey);
        }

        public void SendSymmetricKey()
        {
            symmetricEncryptor.GenerateNewKey();
            string key = Convert.ToBase64String(symmetricEncryptor.aes.Key);
            string encryptedKey = clientEncryption.Encrypt(key);
            SendData(Packet.Packet.SEND_SYMMETRIC_KEY, encryptedKey);
        }
    }
}