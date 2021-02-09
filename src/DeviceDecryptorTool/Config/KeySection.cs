using System;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class DeviceSection
    {
        public OnlinePinSettings onlinePinSettings { get; internal set; } = new OnlinePinSettings();
    }
}
