using Common.Helpers;
using Common.LoggerManager;
using Decryptors.HELPER;
using Decryptors.HELPER.Extensions;
using Decryptors.HELPER.MSRTrackDecryptor;
using Helpers.Clipboard;
using System;
using System.Diagnostics;

namespace Decryptors.MSR
{
    public class MSRTrack
    {
        public string MsrTrackKsn { get; set; }
        public string MsrTrackIV { get; set; }
        public string MsrEncryptedTrackData { get; set; }
        public string MsrDecryptedTrackData { get; set; }

        private void ConsoleLogger(string consoleLog, string loggerLog = null)
        {
            Debug.WriteLine(consoleLog);
            Console.WriteLine(consoleLog);
            Logger.info(loggerLog is { } ? loggerLog : consoleLog);
        }

        public void Decryption(bool maskTrackData)
        {
            try
            {
                //1234567890|1234567890|12345
                ConsoleLogger($"\r\n==== [ MSR TRACK DECRYPTION ] ====", "==== [ MSR TRACK DECRYPTION ] ====");

                MSRTrackDataDecryptor decryptor = new MSRTrackDataDecryptor();

                ConsoleLogger($"{Utils.FormatStringAsRequired("KSN")}: {MsrTrackKsn}");

                //Console.WriteLine($"DATA     : {msrEncryptedTrackData}");

                // decryptor in action
                byte[] trackInformation = decryptor.DecryptData(MsrTrackKsn, MsrEncryptedTrackData, MsrTrackIV);
                //byte[] trackInformation = decryptor.DecryptData(MsrTrackKsn, MsrEncryptedTrackData);

                string decryptedTrack = ConversionHelper.ByteArrayToHexString(trackInformation);

                //1234567890|1234567890|12345
                ConsoleLogger($"{Utils.FormatStringAsRequired("DECODED")}: {decryptedTrack}", $"{Utils.FormatStringAsRequired("OUTPUT")}: {decryptedTrack}");

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

                    Console.WriteLine();
                    ConsoleLogger("==== [DECRYPTED TRACK DATA] ====");
                    ConsoleLogger($"{Utils.FormatStringAsRequired("PAN")}: {trackInfo?.PANData}");
                    // * EXPIRY-YYMM  : 4
                    ConsoleLogger($"{Utils.FormatStringAsRequired("EXPIRATE")}: {trackInfo?.ExpirationDate}");
                    ConsoleLogger($"{Utils.FormatStringAsRequired("KSN")}: {MsrTrackKsn}");

                    // * SERVICE CODE : 3
                    ConsoleLogger($"{Utils.FormatStringAsRequired("SERV CODE")}: {trackInfo?.ServiceCode}");

                    // *PVKI          : 1
                    // *PVV or Offset : 4
                    // * CVV or* CVC  : 3
                    ConsoleLogger($"{Utils.FormatStringAsRequired("DISCRETIONARY")}: {trackInfo?.DiscretionaryData}");
                    string track2DataPayload = $"{trackInfo?.PANData}={trackInfo?.ExpirationDate}{trackInfo?.ServiceCode}{trackInfo?.DiscretionaryData}";

                    // '*' mask 6-12, 17-24
                    string track2DataMasked = maskTrackData ? StringExtensions.Masked(StringExtensions.Masked(track2DataPayload, 6, 6), 17, 7) : track2DataPayload;
                    ConsoleLogger($"{Utils.FormatStringAsRequired("TRACK2 DATA")}: {track2DataMasked}");

                    //byte[] expectedValue = ConversionHelper.HexToByteArray(MsrDecryptedTrackData);
                    //bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, trackInformation);
                    //Console.WriteLine($"EQUAL        : [{result}]");

                    // copy resulting decrypted track data to clipboard and reprocess
                    if (string.IsNullOrEmpty(MsrDecryptedTrackData))
                    {
                        ClipboardClipper.PushStringToClipboard(decryptedTrack);
                    }
                }
                else
                {
                    Debug.WriteLine("\nNO DECRYPTED TRACK2 DATA !!!");
                    Console.WriteLine("\nNO DECRYPTED TRACK2 DATA !!!");
                }

                //MSRTrackData trackData = decryptor.RetrieveTrackData(trackInformation);
                //Console.WriteLine($"CHOLDER: [{trackData.Name}]");
            }
            catch (Exception e)
            {
                ConsoleLogger($"EXCEPTION: {e.Message}");
            }
        }

        /*private void InternalTesting()
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
        }*/
    }
}
