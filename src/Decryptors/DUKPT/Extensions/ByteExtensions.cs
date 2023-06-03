using System.Linq;
using System.Numerics;

namespace Decryptors.DUPKT
{
    internal static class ByteExtensions
    {
        public static BigInteger ToBigInteger(this byte[] bytes)
        {
            return new BigInteger(bytes.Reverse().Concat(new byte[] { 0 }).ToArray());
        }
    }
}
