using Common.Helpers;
using System;

namespace Common.MSRTrackDecryptor
{
    public interface IMSRTrackDataDecryptor : IDisposable
    {
        byte[] DecryptData(string initialKSN, string cipher);
        MSRTrackDataPayload RetrieveTrackData(byte[] trackInformation);
    }
}
