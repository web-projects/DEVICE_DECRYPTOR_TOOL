using System;
using System.Collections.Generic;
using System.Linq;

namespace DeviceDecryptorTool.Extensions
{
    static public class ArrayExtensions
    {
        public static IEnumerable<int> StartingIndex(this byte[] x, byte[] y)
        {
            IEnumerable<int> index = Enumerable.Range(0, x.Length - y.Length + 1);
            for (int i = 0; i < y.Length; i++)
            {
                index = index.Where(n => x[n + i] == y[i]).ToArray();
            }
            return index;
        }

        public static byte[] TrimEnd(this byte[] x)
        {
            int lastIndex = Array.FindLastIndex(x, b => b != 0);
            Array.Resize(ref x, lastIndex + 1);
            return x;
        }

        public static T[] CombineTwoArrays<T>(T[] a1, T[] a2)
        {
            T[] arrayCombined = new T[a1.Length + a2.Length];
            Array.Copy(a1, 0, arrayCombined, 0, a1.Length);
            Array.Copy(a2, 0, arrayCombined, a1.Length, a2.Length);
            return arrayCombined;
        }

        public static byte[] LeftRotate(byte[] arr)
        {
            byte x = arr[0];
            for (int i = 0; i < (arr.Length - 1); i++)
            {
                arr[i] = arr[i + 1];
            }
            arr[(arr.Length - 1)] = x;

            return arr;
        }

        public static byte[] GetSubArray(byte[] source, int start, int length)
            => source.Skip(start).Take(length).ToArray();

        /// <summary>
        /// Rotate byte array left by one
        /// </summary>
        /// <param name="source">original byte array</param>
        /// <returns>rotated byte array</returns>
        public static byte[] RotateLeft(byte[] source)
            => source.Skip(1).Concat(source.Take(1)).ToArray();

        /// <summary>
        /// Rotate byte array right by one
        /// </summary>
        /// <param name="source">original byte array</param>
        /// <returns>rotated byte array</returns>
        public static byte[] RotateRight(byte[] source)
            => source.Skip(source.Length - 1).Concat(source.Take(source.Length - 1)).ToArray();

        public static byte[] ShiftLeftOneBit(byte[] b)
        {
            byte[] r = new byte[b.Length];
            byte carry = 0;

            for (int i = b.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(b[i] << 1);
                r[i] = (byte)((u & 0xff) + carry);
                carry = (byte)((u & 0xff00) >> 8);
            }

            return r;
        }
    }
}
