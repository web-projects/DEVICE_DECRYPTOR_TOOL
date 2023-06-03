using System;

namespace DeviceDecryptorTool.Config
{
    [Serializable]
    public class Application
    {
        public Colors Colors { get; set; }
        public ExecutionMode.Execution ExecutionMode { get; set; } = Config.ExecutionMode.Execution.TrackData;
    }

    [Serializable]
    public class Colors
    {
        public string ForeGround { get; set; } = "WHITE";
        public string BackGround { get; set; } = "BLUE";
    }
}
