using Common.Helpers;
using System;

namespace Common.OnlinePinDecryptor
{
    public interface IPinDecryptor : IDisposable
    {
        byte[] DecryptData(string initialKSN, string cipher);
        OnlinePinData RetrievePinData(byte[] trackInformation);
    }
}
