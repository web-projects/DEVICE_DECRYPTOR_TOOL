using System;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class AppConfig
    {
        public Application Application { get; set; }
        public LoggerManager LoggerManager { get; set; }
        public OnlinePinGroup OnlinePinGroup { get; internal set; } = new OnlinePinGroup();
        public MSRTrackDataGroup MSRTrackDataGroup { get; internal set; } = new MSRTrackDataGroup();
    }
}
