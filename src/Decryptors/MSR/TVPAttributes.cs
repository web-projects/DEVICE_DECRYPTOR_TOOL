namespace Decryptors.MSR
{
    public class TVPAttributes
    {
        public string KSN { get; set; }
        public string IV { get; set; }
        public string EncryptedData { get; set; }

        public bool HasValidProperties()
            => KSN.Length > 0 && IV.Length > 0 && EncryptedData.Length > 0;
    }
}
