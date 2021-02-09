using DeviceDecryptorTool.Helpers;
using System;

namespace DeviceDecryptorTool.MSRTrackDecryptor
{
    public interface IMSRTrackDataDecryptor : IDisposable
    {
        byte[] DecryptData(string initialKSN, string cipher);
        MSRTrackData RetrieveTrackData(byte[] trackInformation);
    }
}
