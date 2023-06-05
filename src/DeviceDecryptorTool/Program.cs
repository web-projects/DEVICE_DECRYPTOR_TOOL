using Common.LoggerManager;
using Decryptors.HELPER.HMAC;
using Decryptors.HELPER.MSRTrackDecryptor;
using Decryptors.MSR;
using DeviceDecryptorTool.Config;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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
        private static AppConfig configuration;
        private static TVPAttributes tvpAttributes = new TVPAttributes();

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
            SetupEnvironment();

            // Check for arguments
            if (args.Length >= 1)
            {
                ParseArguments(args);

                if (tvpAttributes.HasValidProperties())
                {
                    // MSR TRACK DATA GROUP
                    MsrTrackDecryptionWithParameters();

                    return;
                }
            }

            ConsoleKeyInfo keypressed = new ConsoleKeyInfo();

            while (keypressed.Key != ConsoleKey.Escape)
            {
                //InternalTesting();
                ConfigurationLoad(0);

                //HMACTest();

                if (configuration.Application.ExecutionMode == ExecutionMode.Execution.TrackData)
                {
                    // MSR TRACK DATA GROUP
                    MsrTrackDecryption();
                }
                else
                {
                    // ONLINE PIN GROUP
                    DecryptOnlinePin();
                }

                // Wait for KEY Press To Complete
                Console.WriteLine("\r\n\r\nPress <ESC> key to exit...");
                keypressed = Console.ReadKey(true);
                Thread.Sleep(100);
            }
        }

        #region --- APPLICATION ENVIRONMENT ---
        private static void SetupEnvironment()
        {
            ConfigurationLoad(0);

            // logger manager
            SetLogging();

            // Screen Colors
            SetScreenColors();

            Console.WriteLine($"\r\n==========================================================================================");
            Console.WriteLine($"{Assembly.GetEntryAssembly().GetName().Name} - Version {Assembly.GetEntryAssembly().GetName().Version}");
            Console.WriteLine($"==========================================================================================\r\n");
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

        private static void ParseArguments(string[] args)
        {
            tvpAttributes = new TVPAttributes();

            // TVP|ksn:' + ksn + '|iv:' + iv + '|vipa:' + vipa
            string[] commandString = args[0].Split('|');

            if (commandString is { } && commandString.Length == 4)
            {
                foreach (string value in commandString)
                {
                    string[] tvpValue = value.Split(':');
                    if (tvpValue is { } && tvpValue.Length == 2)
                    {
                        switch (tvpValue[0])
                        {
                            case "ksn":
                            {
                                tvpAttributes.KSN = tvpValue[1];
                                break;
                            }
                            case "iv":
                            {
                                tvpAttributes.IV = tvpValue[1];
                                break;
                            }
                            case "vipa":
                            {
                                tvpAttributes.EncryptedData = tvpValue[1];
                                break;
                            }
                        }
                    }
                }
            }
        }

        private static void SetLogging()
        {
            try
            {
                //string[] logLevels = GetLoggingLevels(0);
                string[] logLevels = configuration.LoggerManager.Logging.Levels.Split("|");

                if (logLevels.Length > 0)
                {
                    string fullName = Assembly.GetEntryAssembly().Location;
                    string logname = Path.GetFileNameWithoutExtension(fullName) + ".log";
                    string path = Directory.GetCurrentDirectory();
                    string filepath = path + "\\logs\\" + logname;

                    int levels = 0;
                    foreach (string item in logLevels)
                    {
                        foreach (LOGLEVELS level in LogLevels.LogLevelsDictonary.Where(x => x.Value.Equals(item)).Select(x => x.Key))
                        {
                            levels += (int)level;
                        }
                    }

                    Logger.SetFileLoggerConfiguration(filepath, levels);

                    Logger.info($"{Assembly.GetEntryAssembly().GetName().Name} ({Assembly.GetEntryAssembly().GetName().Version}) - LOGGING INITIALIZED.");
                }
            }
            catch (Exception e)
            {
                Logger.error("main: SetupLogging() - exception={0}", e.Message);
            }
        }

        private static void SetScreenColors()
        {
            if (configuration.Application.EnableColors)
            {
                try
                {
                    // Set Foreground color
                    //Console.ForegroundColor = GetColor(configuration.GetSection("Application:Colors").GetValue<string>("ForeGround"));
                    Console.ForegroundColor = GetColor(configuration.Application.Colors.ForeGround);

                    // Set Background color
                    //Console.BackgroundColor = GetColor(configuration.GetSection("Application:Colors").GetValue<string>("BackGround"));
                    Console.BackgroundColor = GetColor(configuration.Application.Colors.BackGround);

                    Console.Clear();
                }
                catch (Exception ex)
                {
                    Logger.error("main: SetScreenColors() - exception={0}", ex.Message);
                }
            }
        }

        private static ConsoleColor GetColor(string color) => color switch
        {
            "BLACK" => ConsoleColor.Black,
            "DARKBLUE" => ConsoleColor.DarkBlue,
            "DARKGREEEN" => ConsoleColor.DarkGreen,
            "DARKCYAN" => ConsoleColor.DarkCyan,
            "DARKRED" => ConsoleColor.DarkRed,
            "DARKMAGENTA" => ConsoleColor.DarkMagenta,
            "DARKYELLOW" => ConsoleColor.DarkYellow,
            "GRAY" => ConsoleColor.Gray,
            "DARKGRAY" => ConsoleColor.DarkGray,
            "BLUE" => ConsoleColor.Blue,
            "GREEN" => ConsoleColor.Green,
            "CYAN" => ConsoleColor.Cyan,
            "RED" => ConsoleColor.Red,
            "MAGENTA" => ConsoleColor.Magenta,
            "YELLOW" => ConsoleColor.Yellow,
            "WHITE" => ConsoleColor.White,
            _ => throw new Exception($"Invalid color identifier '{color}'.")
        };
        #endregion --- APPLICATION ENVIRONMENT ---

        private static void HMACTest()
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

        private static void DecryptOnlinePin()
        {
            // Is there a matching item?
            int activeIndex = configuration.OnlinePinGroup.ActiveIndex;
            if (configuration.OnlinePinGroup.OnlinePinDataList.Count() > activeIndex)
            {
                string onlinePinKsn = configuration.OnlinePinGroup.OnlinePinDataList.ElementAt(activeIndex).KSN;
                string onlinePinPan = configuration.OnlinePinGroup.OnlinePinDataList.ElementAt(activeIndex).PAN;
                string onlineEncryptedPin = configuration.OnlinePinGroup.OnlinePinDataList.ElementAt(activeIndex).EncryptedPin;
                string onlineDecryptedPin = configuration.OnlinePinGroup.OnlinePinDataList.ElementAt(activeIndex).DecryptedPin;

                OnlinePin pinDecryptor = new OnlinePin()
                {
                    OnlinePinKsn = onlinePinKsn,
                    OnlinePinPan = onlinePinPan,
                    OnlineEncryptedPin = onlineEncryptedPin,
                    OnlineDecryptedPin = onlineDecryptedPin
                };

                pinDecryptor.Decryptor();
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

                MSRTrack msrDecryptor = new MSRTrack()
                {
                    MsrTrackKsn = msrTrackKsn,
                    MsrTrackIV = msrTrackIV,
                    MsrEncryptedTrackData = msrEncryptedTrackData,
                    MsrDecryptedTrackData = msrDecryptedTrackData
                };

                msrDecryptor.Decryption(configuration.Application.MaskTrackData);
            }
        }

        private static void MsrTrackDecryptionWithParameters()
        {
            // Is there a matching item?
            int activeIndex = configuration.MSRTrackDataGroup.ActiveIndex;
            if (configuration.MSRTrackDataGroup.MSRTrackDataList.Count() > activeIndex)
            {
                MSRTrack msrDecryptor = new MSRTrack()
                {
                    MsrTrackKsn = tvpAttributes.KSN,
                    MsrTrackIV = tvpAttributes.IV,
                    MsrEncryptedTrackData = tvpAttributes.EncryptedData,
                    MsrDecryptedTrackData = ""
                };

                msrDecryptor.Decryption(configuration.Application.MaskTrackData);
            }
        }
    }
}
