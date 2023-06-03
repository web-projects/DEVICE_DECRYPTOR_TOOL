using System;

namespace Decryptors.HELPER.MSRTrackDecryptor
{
    public interface IMSRTrackDataDecryptor : IDisposable
    {
        byte[] DecryptData(string initialKSN, string cipher, string iv = null);
        MSRTrackData RetrieveTrackData(byte[] trackInformation);
    }
}
