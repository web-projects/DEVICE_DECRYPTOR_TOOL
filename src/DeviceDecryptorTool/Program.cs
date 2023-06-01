using DeviceDecryptorTool.Config;
using DeviceDecryptorTool.Extensions;
using DeviceDecryptorTool.Helpers;
using DeviceDecryptorTool.HMAC;
using DeviceDecryptorTool.MSRTrackDecryptor;
using DeviceDecryptorTool.OnlinePinDecryptor;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace DeviceDecryptorTool
{
    /// <summary>
    /// 
    /// Program to validate MSR Track decryptor for a given swipe transaction
    ///
    /// BDK: 0123456789ABCDEFFEDCBA9876543210
    /// KEY LEN: 32 BYTES
    /// 
    /// DFDF10: ENCRYPTED DATA
    /// dfdf10-50-87a73106f57b8fbdd383a257ed8c713a62bfae83e9b0d202c50fe1f7da8739338c768ba61506c1d3404191c7c8c3016929a0cce6621b95191d5a006382605fb0c17963725b548abc37ffda146e0429e7
    /// KEY LEN: 80 bytes
    /// 
    /// DFDF11: KSN
    /// dfdf11-0a-ffff9876543211000620
    /// KEY LEN: 10 bytes
    /// 
    /// DFDF12: IV DATA
    /// dfdf12-08-a79ddd0ff736b32b
    /// KEY LEN: 8 bytes
    /// 
    /// </summary>
    class Program
    {
        #region --- WINDOWSFORMS ---
        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

        [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalFree(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalLock(IntPtr hMem);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalUnlock(IntPtr hMem);

        // In .NET Framework there was a special case for a few function names and CopyMemory happened to be one of them.
        // The special case was removed in .NET Core: "CopyMemory" becomes "RtlMoveMemory"
        //[DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseClipboard();

        [DllImport("user32.dll")]
        private static extern IntPtr SetClipboardData(uint uFormat, IntPtr data);

        // ReSharper disable InconsistentNaming
        const uint CF_TEXT = 1;
        const uint CF_UNICODETEXT = 13;
        // ReSharper restore InconsistentNaming

        #endregion --- WINDOWSFORMS ---

        private static AppConfig configuration;

        // Actual Transactions
        public static List<MSRTrackPayload> trackPayload = new List<MSRTrackPayload>()
        {
            // TEST: FFFF9876543211000620
            new MSRTrackPayload()
            {
                KSN = "FFFF9876543211000620",
                EncryptedData = "87A73106F57B8FBDD383A257ED8C713A62BFAE83E9B0D202C50FE1F7DA8739338C768BA61506C1D3404191C7C8C3016929A0CCE6621B95191D5A006382605FB0C17963725B548ABC37FFDA146E0429E7",
                DecryptedData = "7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000"
            },
            new MSRTrackPayload()
            {
                KSN = "FFFF987654321100063D",
                EncryptedData = "7D507A729FB58FE67D6E5C829752518A2E3FEE081076E52AAB1B31916AD9EF3A33DFB5930410B6D4240F0E2065EEAA6C93D57C718F1A03A49CACC90693EBE05D311C7638B44A24271C0A9AAF7A3556580767B075FEEC7511B025A5CB644EF3605D6294F81FF47D3",
                DecryptedData = "19143D2F3491E8AA3935333139323335313030343D323530323135303331323334353F3BDFDB053E254233373339203533313932332035313030345E414D45582054455354204341524420414E5349202020202020205E323030383130303831323334353F5D8000"
            }
        };

        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine($"\r\n==========================================================================================");
            Console.WriteLine($"{Assembly.GetEntryAssembly().GetName().Name} - Version {Assembly.GetEntryAssembly().GetName().Version}");
            Console.WriteLine($"==========================================================================================\r\n");

            ConsoleKeyInfo keypressed = new ConsoleKeyInfo();

            while (keypressed.Key != ConsoleKey.Escape)
            {
                //InternalTesting();
                ConfigurationLoad(0);

                //HMACTest();

                // ONLINE PIN GROUP
                //DecryptOnlinePin(configuration, index);

                // MSR TRACK DATA GROUP
                MsrTrackDecryption();

                // Wait for KEY Press To Complete
                Console.WriteLine("\r\n\r\nPress <ESC> key to exit...");
                keypressed = Console.ReadKey(true);
                Thread.Sleep(100);
            }
        }

        static void HMACTest()
        {
            //string message = "FF1BC21071247B4E541EBC406AF03DE2547703F7B2D6719BE51DB8E496FCC74C";
            string message = "F79B76E2CA36DB74CD3DFB614109B82D597959A10A6F728CBEACB55707BBE4A2";
            string secret = "3CBB2F76F3F47B738953AFA541963B72164E40025CD07F2028F525B0005819E5";
            //string outputHash = HMACData.CreateToken(message, secret);
            string outputHash = HMACData.Tokenizer(message, secret);
            Console.WriteLine($"HMAC={outputHash}");
            //Console.Write("HMAC=");
            //foreach (char letter in outputHash)
            //{
            //    // Get the integral value of the character.
            //    int value = Convert.ToInt32(letter);
            //    // Convert the integer value to a hexadecimal value in string form.
            //    Console.Write($"{value:X}");
            //}
            //Console.WriteLine("");
        }

        private static void ConfigurationLoad(int index)
        {
            // Get appsettings.json config.
            configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build()
                .Get<AppConfig>();
        }

        private static void DecryptOnlinePin(IConfiguration configuration, int index)
        {
            var onlinePin = configuration.GetSection("OnlinePinGroup:OnlinePin")
                    .GetChildren()
                    .ToList()
                    .Select(x => new
                    {
                        onlinePinKsn = x.GetValue<string>("KSN"),
                        onlinePinPan = x.GetValue<string>("PAN"),
                        onlineEncryptedPin = x.GetValue<string>("EncryptedPin"),
                        onlineDecryptedPin = x.GetValue<string>("DecryptedPin")
                    });

            // Is there a matching item?
            if (onlinePin.Count() > index)
            {
                string onlinePinKsn = onlinePin.ElementAt(index).onlinePinKsn;
                string onlinePinPan = onlinePin.ElementAt(index).onlinePinPan;
                string onlineEncryptedPin = onlinePin.ElementAt(index).onlineEncryptedPin;
                string onlineDecryptedPin = onlinePin.ElementAt(index).onlineDecryptedPin;

                try
                {
                    //1234567890|1234567890|12345
                    Console.WriteLine($"==== [ ONLINE PIN DECRYPTION ] ====");

                    PinDecryptor decryptor = new PinDecryptor();

                    Debug.WriteLine($"KSN      : {onlinePinKsn}");
                    Console.WriteLine($"KSN      : {onlinePinKsn}");
                    Console.WriteLine($"DATA     : {onlineEncryptedPin}");

                    // decryptor in action
                    byte[] pinInformation = decryptor.DecryptData(onlinePinKsn, onlineEncryptedPin);

                    string decryptedPin = ConversionHelper.ByteArrayToHexString(pinInformation);

                    //1234567890|1234567890|12345
                    Console.WriteLine($"OUTPUT   : {decryptedPin}");
                    Debug.WriteLine($"OUTPUT ____: {decryptedPin}");

                    Helpers.OnlinePinData pinInfo = decryptor.RetrievePinData(pinInformation);

                    //1234567890|1234567890|12345
                    Debug.WriteLine($"PAN DATA   : {pinInfo.PANData}");

                    byte[] expectedValue = ConversionHelper.HexToByteArray(onlineDecryptedPin);
                    bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, pinInformation);
                    Console.WriteLine($"EQUAL ___: [{result}]");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"EXCEPTION: {e.Message}");
                }
            }
        }

        private static void MsrTrackDecryption()
        {
            // Is there a matching item?
            int activeIndex = configuration.MSRTrackDataGroup.ActiveIndex;
            if (configuration.MSRTrackDataGroup.MSRTrackDataList.Count() > activeIndex)
            {
                string msrTrackKsn = configuration.MSRTrackDataGroup.MSRTrackDataList.ElementAt(activeIndex).KSN;
                string msrTrackIV = configuration.MSRTrackDataGroup.MSRTrackDataList.ElementAt(activeIndex).IV;
                string msrEncryptedTrackData = configuration.MSRTrackDataGroup.MSRTrackDataList.ElementAt(activeIndex).EncryptedTrackData;
                string msrDecryptedTrackData = configuration.MSRTrackDataGroup.MSRTrackDataList.ElementAt(activeIndex).DecryptedTrackData;

                try
                {
                    //1234567890|1234567890|12345
                    Console.WriteLine($"\r\n==== [ MSR TRACK DECRYPTION ] ====");

                    MSRTrackDataDecryptor decryptor = new MSRTrackDataDecryptor();

                    Debug.WriteLine($"KSN _______: {msrTrackKsn}");
                    Console.WriteLine($"KSN      : {msrTrackKsn}");
                    //Console.WriteLine($"DATA     : {msrEncryptedTrackData}");

                    // decryptor in action
                    byte[] trackInformation = decryptor.DecryptData(msrTrackKsn, msrEncryptedTrackData, msrTrackIV);
                    //byte[] trackInformation = decryptor.DecryptData(msrTrackKsn, msrEncryptedTrackData);

                    string decryptedTrack = ConversionHelper.ByteArrayToHexString(trackInformation);

                    //1234567890|1234567890|12345
                    Console.WriteLine($"DECODED  : {decryptedTrack}");
                    Debug.WriteLine($"OUTPUT ____: {decryptedTrack}");

                    //MSRTrackData trackInfo = decryptor.RetrieveAdditionalData(trackInformation);
                    //MSRTrackData trackInfo = decryptor.RetrieveTrackData(trackInformation);
                    MSRTrackData trackInfo = decryptor.RetrieveFromTLV(trackInformation);

                    string expirationDate = "";

                    if (trackInfo?.ExpirationDate?.Length >= 4)
                    {
                        expirationDate = trackInfo.ExpirationDate.Substring(0, 2) + "/" + trackInfo.ExpirationDate.Substring(2, 2);
                    }

                    //1234567890|1234567890|12345
                    if (trackInfo is { })
                    {
                        Debug.WriteLine($"PAN DATA     : {trackInfo?.PANData}");
                        Debug.WriteLine($"EXPIR (YY/MM): {expirationDate}");
                        Debug.WriteLine($"SERVICE CODE : {trackInfo?.ServiceCode}");
                        Debug.WriteLine($"DISCRETIONARY: {trackInfo?.DiscretionaryData}");
                    }

                    if (!string.IsNullOrEmpty(msrDecryptedTrackData) && trackInfo is { })
                    {
                        Console.WriteLine();
                        Console.WriteLine("==== [DECRYPTED TRACK DATA] ====");
                        Console.WriteLine($"PAN          : {trackInfo?.PANData}");
                        // * EXPIRY-YYMM  : 4
                        Console.WriteLine($"EXPIRATE     : {trackInfo?.ExpirationDate}");
                        // * SERVICE CODE : 3
                        Console.WriteLine($"SERV CODE    : {trackInfo?.ServiceCode}"); byte[] expectedValue = ConversionHelper.HexToByteArray(msrDecryptedTrackData);
                        // *PVKI          : 1
                        // *PVV or Offset : 4
                        // * CVV or* CVC  : 3
                        Console.WriteLine($"DISCRETIONARY: {trackInfo?.DiscretionaryData}");
                        string track2DataPayload = $"{trackInfo?.PANData}={trackInfo?.ExpirationDate}{trackInfo?.ServiceCode}{trackInfo?.DiscretionaryData}";
                        // '*' mask 6-12, 17-24
                        string track2DataMasked = StringExtensions.Masked(StringExtensions.Masked(track2DataPayload, 6, 6), 17, 7);
                        Console.WriteLine($"TRACK2 DATA  : {track2DataMasked}");

                        //bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, trackInformation);
                        //Console.WriteLine($"EQUAL        : [{result}]");
                    }
                    else
                    {
                        Debug.WriteLine("\nNO TRACK2 DATA !!!");
                        Console.WriteLine("\nNO TRACK2 DATA !!!");

                        // copy resulting decrypted track data to clipboard and reprocess
                        Result result = PushStringToClipboard(decryptedTrack);
                    }

                    //MSRTrackData trackData = decryptor.RetrieveTrackData(trackInformation);
                    //Console.WriteLine($"CHOLDER: [{trackData.Name}]");
                }
                catch (Exception e)
                {
                    Debug.WriteLine($"EXCEPTION: {e.Message}");
                    Console.WriteLine($"EXCEPTION: {e.Message}");
                }
            }
        }

        [STAThread]
        public static Result PushStringToClipboard(string message)
        {
            var isAscii = (message != null && (message == Encoding.ASCII.GetString(Encoding.ASCII.GetBytes(message))));
            if (isAscii)
            {
                return PushUnicodeStringToClipboard(message);
            }
            else
            {
                return PushAnsiStringToClipboard(message);
            }
        }

        [STAThread]
        public static Result PushUnicodeStringToClipboard(string message)
        {
            return __PushStringToClipboard(message, CF_UNICODETEXT);
        }

        [STAThread]
        public static Result PushAnsiStringToClipboard(string message)
        {
            return __PushStringToClipboard(message, CF_TEXT);
        }

        [STAThread]
        private static Result __PushStringToClipboard(string message, uint format)
        {
            OpenClipboard(IntPtr.Zero);
            //IntPtr ptr = Marshal.StringToHGlobalUni(source);
            //SetClipboardData(13, ptr);
            //CloseClipboard();
            //Marshal.FreeHGlobal(ptr);
            try
            {
                try
                {
                    if (message is null)
                    {
                        return new Result { ResultCode = ResultCode.ErrorInvalidArgs };
                    }

                    if (!OpenClipboard(IntPtr.Zero))
                    {
                        return new Result { ResultCode = ResultCode.ErrorOpenClipboard, LastError = GetLastError() };
                    }

                    try
                    {
                        uint sizeOfChar;
                        switch (format)
                        {
                            case CF_TEXT:
                            sizeOfChar = 1;
                            break;
                            case CF_UNICODETEXT:
                            sizeOfChar = 2;
                            break;
                            default:
                            throw new Exception("Not Reachable");
                        }

                        var characters = (uint)message.Length;
                        uint bytes = (characters + 1) * sizeOfChar;

                        // ReSharper disable once InconsistentNaming
                        const int GMEM_MOVABLE = 0x0002;
                        // ReSharper disable once InconsistentNaming
                        const int GMEM_ZEROINIT = 0x0040;
                        // ReSharper disable once InconsistentNaming
                        const int GHND = GMEM_MOVABLE | GMEM_ZEROINIT;

                        // IMPORTANT: SetClipboardData requires memory that was acquired with GlobalAlloc using GMEM_MOVABLE.
                        IntPtr hGlobal = NewMethod(bytes, GHND);
                        if (hGlobal == IntPtr.Zero)
                        {
                            return new Result { ResultCode = ResultCode.ErrorGlobalAlloc, LastError = GetLastError() };
                        }

                        try
                        {
                            // IMPORTANT: Marshal.StringToHGlobalUni allocates using LocalAlloc with LMEM_FIXED.
                            //            Note that LMEM_FIXED implies that LocalLock / LocalUnlock is not required.
                            IntPtr source;
                            switch (format)
                            {
                                case CF_TEXT:
                                source = Marshal.StringToHGlobalAnsi(message);
                                break;
                                case CF_UNICODETEXT:
                                source = Marshal.StringToHGlobalUni(message);
                                break;
                                default:
                                throw new Exception("Not Reachable");
                            }

                            try
                            {
                                IntPtr target = NewMethod1(hGlobal);

                                if (target == IntPtr.Zero)
                                {
                                    return new Result { ResultCode = ResultCode.ErrorGlobalLock, LastError = GetLastError() };
                                }

                                try
                                {
                                    CopyMemory(target, source, bytes);
                                }
                                finally
                                {
                                    var ignore = GlobalUnlock(target);
                                }

                                if (SetClipboardData(format, hGlobal).ToInt64() != 0)
                                {
                                    // IMPORTANT: SetClipboardData takes ownership of hGlobal upon success.
                                    hGlobal = IntPtr.Zero;
                                }
                                else
                                {
                                    return new Result { ResultCode = ResultCode.ErrorSetClipboardData, LastError = GetLastError() };
                                }
                            }
                            finally
                            {
                                // Marshal.StringToHGlobalUni actually allocates with LocalAlloc, thus we should theorhetically use LocalFree to free the memory...
                                // ... but Marshal.FreeHGlobal actully uses a corresponding version of LocalFree internally, so this works, even though it doesn't
                                //  behave exactly as expected.
                                Marshal.FreeHGlobal(source);
                            }
                        }
                        catch (OutOfMemoryException)
                        {
                            return new Result { ResultCode = ResultCode.ErrorOutOfMemoryException, LastError = GetLastError() };
                        }
                        catch (ArgumentOutOfRangeException)
                        {
                            return new Result { ResultCode = ResultCode.ErrorArgumentOutOfRangeException, LastError = GetLastError() };
                        }
                        finally
                        {
                            if (hGlobal != IntPtr.Zero)
                            {
                                var ignore = GlobalFree(hGlobal);
                            }
                        }
                    }
                    finally
                    {
                        CloseClipboard();
                    }
                    return new Result { ResultCode = ResultCode.Success };
                }
                catch (Exception ex)
                {
                    return new Result { ResultCode = ResultCode.ErrorException, LastError = GetLastError() };
                }
            }
            catch (Exception)
            {
                return new Result { ResultCode = ResultCode.ErrorGetLastError };
            }
        }

        private static IntPtr NewMethod1(IntPtr hGlobal)
        {
            return GlobalLock(hGlobal);
        }

        private static IntPtr NewMethod(uint bytes, uint GHND)
        {
            return GlobalAlloc(GHND, (UIntPtr)bytes);
        }

        private static void InternalTesting()
        {
            try
            {
                foreach (var item in trackPayload)
                {
                    MSRTrackDataDecryptor decryptor = new MSRTrackDataDecryptor();

                    // decryptor in action
                    byte[] trackInformation = decryptor.DecryptData(item.KSN, item.EncryptedData);

                    string decryptedTrack = ConversionHelper.ByteArrayToHexString(trackInformation);

                    //1234567890|1234567890|12345
                    Debug.WriteLine($"OUTPUT ____: {decryptedTrack}");
                    Console.WriteLine($"OUTPUT : [{decryptedTrack}]");

                    byte[] expectedValue = ConversionHelper.HexToByteArray(item.DecryptedData);
                    bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, trackInformation);
                    Console.WriteLine($"EQUAL  : [{result}]");

                    Helpers.MSRTrackData trackData = decryptor.RetrieveTrackData(trackInformation);
                    Console.WriteLine($"CHOLDER: [{trackData.Name}]");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"EXCEPTION: {e.Message}");
            }
        }
    }
}
