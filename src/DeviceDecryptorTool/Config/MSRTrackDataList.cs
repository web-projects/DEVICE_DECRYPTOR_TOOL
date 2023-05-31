using System;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class MSRTrackDataList
    {
        public string KSN { get; set; }
        public string IV { get; set; }
        public string EncryptedTrackData { get; set; }
        public string DecryptedTrackData { get; set; }
    }
}
