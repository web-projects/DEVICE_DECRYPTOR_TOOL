using DeviceDecryptorTool.Config.LoggingConfig;
using System;

namespace DeviceDecryptorTool.Config.ApplicationConfig
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
