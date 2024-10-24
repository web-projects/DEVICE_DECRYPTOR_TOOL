using System;

namespace Config
{
    [Serializable]
    public class WindowPosition
    {
        public string Top { get; set; }
        public string Left { get; set; }
        public string Height { get; set; }
        public string Width { get; set; }
    }
}
