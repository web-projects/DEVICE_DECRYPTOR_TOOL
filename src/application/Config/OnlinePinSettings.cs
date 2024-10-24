using System;
using System.Collections.Generic;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class OnlinePinSettings
    {
        public List<string> OnlinePinGroup { get; internal set; } = new List<string>();
    }
}
