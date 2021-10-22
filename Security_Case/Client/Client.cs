using Packet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Client
{
    class Client
    {
        private TcpClient socket;
        private NetworkStream stream;


        private Encryption clientEncryption = new Encryption();

        string serverPublicKeyPath = Directory.GetCurrentDirectory() + "\\Server Public Key.txt";
        private Encryption serverEncryption = new Encryption();


        private AesEncryptor symmetricEncryptor = new AesEncryptor();


        public bool isReadyToSendMessage = false;

        public Client()
        {
            isReadyToSendMessage = false;


            LoadServerPublicKey();
        }

        public void LoadServerPublicKey()
        {
            if (File.Exists(serverPublicKeyPath))
            {
                string serverPublicKeyLoaded = File.ReadAllText(serverPublicKeyPath);
                serverEncryption.publicKey = serverEncryption.ConvertStringToKey(serverPublicKeyLoaded);
            }
        }

        public void Connect(string ip, int port)
        {
            try
            {

                socket = new TcpClient(ip, port);

                stream = socket.GetStream();
                Console.WriteLine("Connected To Server");

                stream.BeginRead(Constant.dataBuffer, 0, Constant.dataBuffer.Length, ReceiveData, null);


                clientEncryption.GenerateKey();


                SendPublicKey();

                Console.WriteLine($"Sending Client Public Key to Server");
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e);
            }
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
                Console.WriteLine($"Error while receiving TCP data: {_ex}");
                
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
                case (int)Packet.Packet.SEND_SYMMETRIC_KEY:
                    
                    string keyString = Encoding.ASCII.GetString(messageData);
                    
                    string decrypted = clientEncryption.Decrypt(keyString);
                    Console.WriteLine($"{decrypted}");
                    symmetricEncryptor.SetKey(Convert.FromBase64String(decrypted));
                    isReadyToSendMessage = true;
                    SendMessage("Hello!");
                    break;

                case (int)Packet.Packet.SEND_MESSAGE:
                    string message = Encoding.ASCII.GetString(messageData, 0, messageData.Length);
                    string decryptedMsg = symmetricEncryptor.Decrypt(message);
                    Console.WriteLine($"Message from server: {decryptedMsg}");
                    break;

                default:
                    break;
            }
        }

        private void SendData(Packet.Packet packet, string data)
        {
            
            List<byte> dataToSend = new List<byte>();
            dataToSend.AddRange(BitConverter.GetBytes((int)packet));
            dataToSend.AddRange(Encoding.ASCII.GetBytes(data));

            
            stream.Write(dataToSend.ToArray(), 0, dataToSend.Count);
        }

        private void SendPublicKey()
        {
            string clientPublicKeyOnString = clientEncryption.ConvertKeyToString(clientEncryption.publicKey);
            string encryptedKey = serverEncryption.Encrypt(clientPublicKeyOnString);
            Console.WriteLine($"\nSending Client Public Key...");
            SendData(Packet.Packet.SEND_KEY, encryptedKey);
        }
        public void SendMessage(string msg)
        {
            if (!isReadyToSendMessage) return;

            string encryptedWithSymKey = symmetricEncryptor.Encrypt(msg);
            SendData(Packet.Packet.SEND_MESSAGE, encryptedWithSymKey);
        }

    }
}
