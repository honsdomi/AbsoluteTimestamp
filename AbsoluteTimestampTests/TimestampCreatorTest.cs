using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using AbsoluteTimestamp;
using System.IO;

namespace TimestampLibraryTests
{
    [TestClass]
    public class TimestampCreatorTest
    {
        private const string dataToTimestamp = "Test string to timestamp.";
        private const string tsaUrl1 = "http://tsa.cesnet.cz:3161/tsa"; //microsoft cert validation fails
        private const string tsaUrl2 = "http://time.certum.pl"; //microsoft cert validation is OK
        private const string tsaUrl3 = "http://zeitstempel.dfn.de/"; //has crl but without revocation reason

        [TestMethod]
        public void TestCreateTimestampSimple()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);

            TimestampCreator creator = new TimestampCreator();
            TimestampObject timestamp = creator
                .SetTsaPrimaryUrl(tsaUrl2)
                .SetHashAlgorithm(HashAlgorithm.SHA1)
                .SetOutputFormat(OutputFormat.TSR)
                .SetDataForTimestamping(data)
                .CreateTimestamp();

            Assert.AreEqual(HashAlgorithm.SHA1, timestamp.HashAlgorithm);

            timestamp = creator
                .SetHashAlgorithm(HashAlgorithm.SHA256)
                .CreateTimestamp();

            Assert.AreEqual(HashAlgorithm.SHA256, timestamp.HashAlgorithm);
        }

        [TestMethod]
        public void TestCreateTimestampFromDigest()
        {
            byte[] digest = new System.Security.Cryptography.SHA1Cng().ComputeHash(Encoding.UTF8.GetBytes(dataToTimestamp));

            TimestampCreator creator = new TimestampCreator();
            TimestampObject timestamp = creator
                .SetTsaPrimaryUrl(tsaUrl2)
                .SetHashAlgorithm(HashAlgorithm.SHA1)
                .SetOutputFormat(OutputFormat.TSR)
                .SetMessageDigestForTimestamping(digest)
                .CreateTimestamp();
        }

        [TestMethod]
        public void TestCreateTimestampUsingConfigurationFile()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);
            Utils.LoadConfigurationFile(Directory.GetParent(Directory.GetCurrentDirectory()).Parent.Parent.FullName +  "\\src\\configuration.txt");
            TimestampCreator creator = new TimestampCreator();
            TimestampObject timestamp = creator
                .SetDataForTimestamping(data)
                .CreateTimestamp();

            Assert.AreEqual(HashAlgorithm.SHA1, timestamp.HashAlgorithm);

            timestamp = creator
                .SetHashAlgorithm(HashAlgorithm.SHA256)
                .CreateTimestamp();

            Assert.AreEqual(HashAlgorithm.SHA256, timestamp.HashAlgorithm);
        }

        [TestMethod]
        public void TestCreateTimestampAndCheckWarning()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);

            TimestampCreator creator = new TimestampCreator();
            TimestampObject timestamp = creator
                .SetTsaPrimaryUrl(tsaUrl2)
                .SetHashAlgorithm(HashAlgorithm.SHA1)
                .SetOutputFormat(OutputFormat.TSR)
                .SetDataForTimestamping(data)
                .SetMinimimCertificateValidityPeriod(180)
                .CreateTimestamp();

            Assert.IsNull(timestamp.Warning);

            timestamp = creator
                .SetHashAlgorithm(HashAlgorithm.SHA256)
                .SetMinimimCertificateValidityPeriod(4000)
                .CreateTimestamp();

            Assert.IsNotNull(timestamp.Warning);
        }

        [TestMethod]
        [ExpectedException(typeof(AggregateException))]
        public void TestCreateWrongUrl()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);

            TimestampCreator creator = new TimestampCreator();
            TimestampObject timestamp = creator
                .SetTsaPrimaryUrl("http://wrong.url")
                .SetTsaSecondaryUrl("http://alsowrong.url")
                .SetHashAlgorithm(HashAlgorithm.SHA1)
                .SetOutputFormat(OutputFormat.TSR)
                .SetDataForTimestamping(data)
                .CreateTimestamp();
        }

        [TestMethod]
        public void TestCreateTimestampSecondaryTsa()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);

            TimestampCreator creator = new TimestampCreator();
            TimestampObject timestamp = creator
                .SetTsaPrimaryUrl("http://www.google.com:81")
                .SetTsaSecondaryUrl(tsaUrl2)
                .SetTsaTimeout(1000 * 3)
                .SetHashAlgorithm(HashAlgorithm.SHA1)
                .SetOutputFormat(OutputFormat.TSR)
                .SetDataForTimestamping(data)
                .CreateTimestamp();

            Assert.AreEqual(timestamp.TsaIssuer, "C=PL,O=Unizeto Technologies S.A.,OU=Certum Certification Authority,CN=Certum Trusted Network CA");
        }
        
    }
}
