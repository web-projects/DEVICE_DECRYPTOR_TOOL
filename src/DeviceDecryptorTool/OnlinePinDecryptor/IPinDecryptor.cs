using DeviceDecryptorTool.Helpers;
using System;

namespace DeviceDecryptorTool.OnlinePinDecryptor
{
    public interface IPinDecryptor : IDisposable
    {
        byte[] DecryptData(string initialKSN, string cipher);
        OnlinePinData RetrievePinData(byte[] trackInformation);
    }
}
