using Common.Helpers;

namespace DeviceDecryptorTool.Config
{
    public class ExecutionMode
    {
        public enum Execution
        {
            [StringValue("Undefined")]
            Undefined,
            [StringValue("TrackData")]
            TrackData,
            [StringValue("PinData")]
            PinData,
        }
    }
}
