using System;

namespace Decryptors.HELPER.OnlinePinDecryptor
{
    public interface IPinDecryptor : IDisposable
    {
        byte[] DecryptData(string initialKSN, string cipher);
        OnlinePinData RetrievePinData(string panData, byte[] trackInformation);
    }
}
