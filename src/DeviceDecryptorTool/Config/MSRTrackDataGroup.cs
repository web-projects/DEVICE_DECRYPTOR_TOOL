using System;
using System.Collections.Generic;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class MSRTrackDataGroup
    {
        public int ActiveIndex { get; set; } = 0;
        public List<MSRTrackDataList> MSRTrackDataList { get; internal set; } = new List<MSRTrackDataList>();
    }
}
