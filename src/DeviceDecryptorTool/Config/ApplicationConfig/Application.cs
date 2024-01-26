using DeviceDecryptorTool.Config.Application;
using System;

namespace DeviceDecryptorTool.Config.ApplicationConfig
{
    [Serializable]
    public class Application
    {
        public Colors Colors { get; set; }
        public bool EnableColors { get; set; }
        public WindowPosition WindowPosition { get; set; }
        public bool MaskTrackData { get; set; }
        public ExecutionMode.Execution ExecutionMode { get; set; } = Config.ExecutionMode.Execution.TrackData;
    }

    [Serializable]
    public class Colors
    {
        public string ForeGround { get; set; } = "WHITE";
        public string BackGround { get; set; } = "BLUE";
    }
}
