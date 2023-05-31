using System;
using System.Collections.Generic;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class AppConfig
    {
        public OnlinePinGroup OnlinePinGroup { get; internal set; } = new OnlinePinGroup();
        public MSRTrackDataGroup MSRTrackDataGroup { get; internal set; } = new MSRTrackDataGroup();
    }
}
