namespace Decryptors.HELPER.Extensions
{
    public static class StringExtensions
    {
        private const char maskChar = '*';

        public static string Masked(this string source, int start, int count)
        {
            return source.Masked(maskChar, start, count);
        }

        public static string Masked(this string source, char maskValue, int start, int count)
        {
            string firstPart = source.Substring(0, start);
            string lastPart = source.Substring(start + count);
            string middlePart = new string(maskValue, count);

            return firstPart + middlePart + lastPart;
        }
    }
}
