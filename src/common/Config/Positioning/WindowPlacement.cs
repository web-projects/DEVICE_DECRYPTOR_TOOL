using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Config.Positioning
{
    public static class WindowPlacement
    {
        #region --- Win32 API ---
        [StructLayout(LayoutKind.Sequential)]
        public struct Rect
        {
            public int Left;        // x position of upper-left corner
            public int Top;         // y position of upper-left corner
            public int Right;       // x position of lower-right corner
            public int Bottom;      // y position of lower-right corner
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll", SetLastError = true)]
        internal static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

        [DllImport("user32.dll", EntryPoint = "GetWindowPos")]
        public static extern uint GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", EntryPoint = "SetWindowPos")]
        public static extern IntPtr SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int x, int Y, int cx, int cy, int wFlags);

        [DllImport("user32.dll")]
        public static extern bool GetWindowRect(IntPtr hwnd, ref Rect rectangle);

        #endregion --- Win32 API ---

        public static void RestoreWindowPosition(AppConfig configuration)
        {
            IntPtr ptr = GetConsoleWindow();

            Rect parentWindowRectangle = new Rect()
            {
                Top = Convert.ToInt16(configuration.Application.WindowPosition.Top),
                Left = Convert.ToInt16(configuration.Application.WindowPosition.Left),
                Right = Convert.ToInt16(configuration.Application.WindowPosition.Width),
                Bottom = Convert.ToInt16(configuration.Application.WindowPosition.Height),
            };

            // int X, int Y, int nWidth, int nHeight
            MoveWindow(ptr,
                       parentWindowRectangle.Left, parentWindowRectangle.Top,
                       parentWindowRectangle.Right, parentWindowRectangle.Bottom,
                       true);
        }

        public static void SaveWindowPosition(AppConfig configuration)
        {
            IntPtr ptr = GetConsoleWindow();
            Rect parentWindowRectangle = new Rect();
            GetWindowRect(ptr, ref parentWindowRectangle);

            configuration.Application.WindowPosition.Top = Convert.ToString(parentWindowRectangle.Top);
            configuration.Application.WindowPosition.Left = Convert.ToString(parentWindowRectangle.Left);
            configuration.Application.WindowPosition.Height = Convert.ToString(parentWindowRectangle.Bottom - parentWindowRectangle.Top);
            configuration.Application.WindowPosition.Width = Convert.ToString(parentWindowRectangle.Right - parentWindowRectangle.Left);

            AppSettingsUpdate(configuration);
        }

        private static void AppSettingsUpdate(AppConfig configuration)
        {
            try
            {
                var jsonWriteOptions = new JsonSerializerOptions()
                {
                    WriteIndented = true
                };
                jsonWriteOptions.Converters.Add(new JsonStringEnumConverter());

                string newJson = JsonSerializer.Serialize(configuration, jsonWriteOptions);
                Debug.WriteLine($"{newJson}");

                string appSettingsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json");
                File.WriteAllText(appSettingsPath, newJson);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in saving settings: {ex}");
            }
        }
    }
}
