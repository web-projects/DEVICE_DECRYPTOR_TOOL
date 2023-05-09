using System;
using System.Text;

namespace DeviceDecryptorTool.DukptNet.Test
{
    public static class Helpers
    {
        public static string ByteArrayToAsciiString(byte[] value)
        {
            return UnicodeEncoding.ASCII.GetString(value);
        }

        public static string ByteArrayToHexString(byte[] value)
        {
            return BitConverter.ToString(value).Replace("-", "");
        }

        public static string ByteArrayCodedHextoString(byte[] data)
        {
            StringBuilder result = new StringBuilder(data.Length);

            foreach (byte value in data)
            {
                // 0-1 : 0x30-0x39
                // a-f : 0x61-0x66
                // A-F : 0x41-0x46
                result.Append((char)Convert.ToInt32(value));
            }

            return result.ToString();
        }
    }
}
