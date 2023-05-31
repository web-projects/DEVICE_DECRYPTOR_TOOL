using System;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class OnlinePinDataList
    {
        public string KSN { get; set; }
        public string PAN { get; set; }
        public string EncryptedPin { get; set; }
        public string DecryptedPin { get; set; }
    }
}
