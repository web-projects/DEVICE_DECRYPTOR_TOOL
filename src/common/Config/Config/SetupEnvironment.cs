using Config.Positioning;
using Common.LoggerManager;
using Microsoft.Extensions.Configuration;
using System;
using System.Reflection;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Config
{
    public static class SetupEnvironment
    {
        private static AppConfig configuration;

        private static string sourceDirectory;
        private static string workingDirectory;
        private static string logfilenamePath;

        public static void SetEnvironment()
        {
            Console.WriteLine($"\r\n==========================================================================================");
            Console.WriteLine($"{Assembly.GetEntryAssembly().GetName().Name} - Version {Assembly.GetEntryAssembly().GetName().Version}");
            Console.WriteLine($"==========================================================================================\r\n");

            ConfigurationLoad();

            // Screen Colors
            SetScreenColors(true);

            // Screen Position
            WindowPlacement.RestoreWindowPosition(configuration);

            // logger manager
            SetLogging();
        }

        public static void SaveEnvironment()
            => WindowPlacement.SaveWindowPosition(configuration);

        // Get appsettings.json config.
        public static void ConfigurationLoad()
            =>  configuration = new ConfigurationBuilder()
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .AddEnvironmentVariables()
                    .Build()
                    .Get<AppConfig>();

        public static AppConfig GetApplicationConfiguration()
            => configuration;

        #region --- APPLICATION ENVIRONMENT ---
        private static void SetScreenColors(bool clearConsole)
        {
            if (configuration?.Application?.EnableColors ?? false)
            {
                try
                {
                    // Set Foreground color
                    //Console.ForegroundColor = GetColor(configuration.GetSection("Application:Colors").GetValue<string>("ForeGround"));
                    Console.ForegroundColor = GetColor(configuration.Application.Colors.ForeGround);

                    // Set Background color
                    //Console.BackgroundColor = GetColor(configuration.GetSection("Application:Colors").GetValue<string>("BackGround"));
                    Console.BackgroundColor = GetColor(configuration.Application.Colors.BackGround);

                    if (clearConsole)
                    {
                        Console.Clear();
                    }
                }
                catch (Exception ex)
                {
                    //Logger.error("main: SetScreenColors() - exception={0}", ex.Message);
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
                    logfilenamePath = path + "\\logs\\" + logname;

                    int levels = 0;
                    foreach (string item in logLevels)
                    {
                        foreach (LOGLEVELS level in LogLevels.LogLevelsDictonary.Where(x => x.Value.Equals(item)).Select(x => x.Key))
                        {
                            levels += (int)level;
                        }
                    }

                    Logger.SetFileLoggerConfiguration(logfilenamePath, levels);

                    Logger.info($"{Assembly.GetEntryAssembly().GetName().Name} ({Assembly.GetEntryAssembly().GetName().Version}) - LOGGING INITIALIZED.");
                }
            }
            catch (Exception e)
            {
                Logger.error("main: SetupLogging() - exception={0}", e.Message);
            }
        }

        public static async Task WaitForEscapeKeyPress()
        {
            Console.WriteLine("\r\n\r\nPress <ESC> key to exit...");

            while (true)
            {
                ConsoleKeyInfo keyPressed = Console.ReadKey(true);

                if (keyPressed.Key == ConsoleKey.Escape)
                {
                    break;
                }

                await Task.Delay(100);
            }

            Console.WriteLine("APPLICATION EXITING ...");
            Console.WriteLine("");
        }

        #endregion --- APPLICATION ENVIRONMENT ---
    }
}
