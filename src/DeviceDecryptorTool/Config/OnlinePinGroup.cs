using System;
using System.Collections.Generic;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class OnlinePinGroup
    {
        public int ActiveIndex { get; set; } = 0;
        public List<OnlinePinDataList> OnlinePinDataList { get; internal set; } = new List<OnlinePinDataList>();
    }
}
