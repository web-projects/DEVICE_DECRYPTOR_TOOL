using System;
using System.Security.Cryptography;

namespace DeviceDecryptorTool.HMAC
{
    public static class HMACData
    {
        public static string CreateToken(string message, string secret)
        {
            secret = secret ?? "";
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }

        public static string Tokenizer(string message, string secret)
        {
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();

            byte[] keyByte = encoding.GetBytes(secret);

            HMACMD5 hmacmd5 = new HMACMD5(keyByte);
            HMACSHA1 hmacsha1 = new HMACSHA1(keyByte);
            HMACSHA256 hmacsha256 = new HMACSHA256(keyByte);
            HMACSHA384 hmacsha384 = new HMACSHA384(keyByte);
            HMACSHA512 hmacsha512 = new HMACSHA512(keyByte);

            byte[] messageBytes = encoding.GetBytes(message);

            byte[] hashmessage = hmacmd5.ComputeHash(messageBytes);

            string hmac1 = ByteToString(hashmessage);

            hashmessage = hmacsha1.ComputeHash(messageBytes);

            string hmac2 = ByteToString(hashmessage);

            hashmessage = hmacsha256.ComputeHash(messageBytes);

            string hmac3 = ByteToString(hashmessage);

            hashmessage = hmacsha384.ComputeHash(messageBytes);

            string hmac4 = ByteToString(hashmessage);

            hashmessage = hmacsha512.ComputeHash(messageBytes);

            string hmac5 = ByteToString(hashmessage);

            return hmac5;
        }

        /*converts byte to encrypted string*/
        public static string ByteToString(byte[] buff)
        {
            string sbinary = "";

            for (int i = 0; i < buff.Length; i++)
            {
                sbinary += buff[i].ToString("X2"); // hex format
            }
            return (sbinary);
        }

        /*Generates a random Number for key*/
        public static int GetRandomNumber(double minimum, double maximum)
        {
            Random random = new Random();
            return Convert.ToInt32(random.NextDouble() * (maximum - minimum) + minimum);
        }
    }
}
