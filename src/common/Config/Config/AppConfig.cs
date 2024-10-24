using System;

namespace Config
{
    [Serializable]
    public class AppConfig
    {
        public Application Application { get; set; }
        public LoggerManager LoggerManager { get; set; }
        public MSRTrackDataGroup MSRTrackDataGroup { get; set; }
    }
}
