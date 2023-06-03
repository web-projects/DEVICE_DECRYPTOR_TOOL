using Common.LoggerManager;
using Decryptors.HELPER;
using Decryptors.HELPER.OnlinePinDecryptor;
using System;
using System.Collections;
using System.Diagnostics;

namespace Decryptors.MSR
{
    public class OnlinePin
    {
        public string OnlinePinKsn { get; set; }
        public string OnlinePinPan { get; set; }
        public string OnlineEncryptedPin { get; set; }
        public string OnlineDecryptedPin { get; set; }

        private void ConsoleLogger(string consoleLog, string loggerLog = null)
        {
            Debug.WriteLine(consoleLog);
            Console.WriteLine(consoleLog);
            Logger.info(loggerLog is { } ? loggerLog : consoleLog);
        }

        public void Decryptor()
        {
            try
            {
                //1234567890|1234567890|12345
                ConsoleLogger($"==== [ ONLINE PIN DECRYPTION ] ====");

                PinDecryptor decryptor = new PinDecryptor();

                ConsoleLogger($"KSN      : {OnlinePinKsn}");
                ConsoleLogger($"DATA     : {OnlineEncryptedPin}");

                // decryptor in action
                byte[] pinInformation = decryptor.DecryptData(OnlinePinKsn, OnlineEncryptedPin);

                string decryptedPin = ConversionHelper.ByteArrayToHexString(pinInformation);

                //1234567890|1234567890|12345
                ConsoleLogger($"OUTPUT __: {decryptedPin}");

                OnlinePinData pinInfo = decryptor.RetrievePinData(OnlinePinPan, pinInformation);

                //1234567890|1234567890|12345
                ConsoleLogger($"PAN DATA : {pinInfo.PANData}");

                byte[] expectedValue = ConversionHelper.HexToByteArray(OnlineDecryptedPin);
                bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, pinInformation);
                ConsoleLogger($"EQUAL ___: [{result}]");
            }
            catch (Exception e)
            {
                ConsoleLogger($"EXCEPTION: {e.Message}");
            }
        }
    }
}
