using DeviceDecryptorTool.Helpers;
using System.Collections.Generic;
using TestHelper;
using Xunit;
using ConversionHelper = TestHelper.ConversionHelper;

namespace DeviceDecryptorTool.OnlinePinDecryptor.Tests
{
    public class OnlinePinDecryptorTests
    {
        readonly PinDecryptor subject;

        public OnlinePinDecryptorTests()
        {
            subject = new PinDecryptor();
        }

        [Theory]
        [InlineData("FFFF9876543211000620", 3)]
        [InlineData("FFFF9876543211000636", 6)]
        [InlineData("FFFF9876543211000637", 7)]
        public void GetTotalEncryptionPasses_ShouldReturnNumberOfPasses_WhenCalled(string ksn, int expectedValue)
        {
            byte[] initialKSN = ConversionHelper.HexToByteArray(ksn);

            Helper.CallPrivateMethod("GetTotalEncryptionPasses", subject, out List<int> passList, new object[] { initialKSN });

            Assert.Equal(expectedValue, passList.Count);
        }

        [Theory]
        [InlineData("F876543210040B800009", "6799998900000074316", "B2449FABB96D4228", "04439CFFFFFF8BCE", "4315")]
        [InlineData("F876543210040B800008", "6799998900000070199", "4BB4136EEA406C2A", "04439CFFFFFF8FE6", "4315")]
        public void DecryptPinData_ShouldDecryptPinData_WhenCalled(string ksn, string pan, string encryptedPinData, string decryptedPinData, string expectedPinValue)
        {
            byte[] expectedValue = ConversionHelper.HexToByteArray(decryptedPinData);

            byte[] actualValue = subject.DecryptData(ksn, encryptedPinData);

            Assert.Equal(expectedValue, actualValue);

            // Decode PIN Block: format ISO-0
            string actualPinValue = decryptedPinData.Substring(2, 2);
            string decryptLastTwo = decryptedPinData.Substring(4);

            // XOR the remainder of the decrypted data trailer with the final 12 digits of the PAN not including the check digit
            string panDigits = pan.Substring(pan.Length - 13, 12);

            byte[] pinLastTwo = ConversionHelper.HexToByteArray(decryptLastTwo);
            byte[] panLastTwelve = ConversionHelper.HexToByteArray(panDigits);

            byte[] pinResult = ConversionHelper.XORArrays(pinLastTwo, panLastTwelve);
            string pinTemp = ConversionHelper.ArrayToHexString(pinResult);

            actualPinValue += pinTemp.Substring(0, 2);

            Assert.Equal(expectedPinValue, actualPinValue);
        }
    }
}