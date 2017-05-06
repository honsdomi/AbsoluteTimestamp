using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.Text;
using AbsoluteTimestamp;

namespace TimestampLibraryTests
{
    [TestClass]
    public class TimestampVerifierTest
    {
        private const string dataToTimestamp = "Test string to timestamp.";
        private const string tsaUrl1 = "http://tsa.cesnet.cz:3161/tsa"; //microsoft cert validation fails
        private const string tsaUrl2 = "http://time.certum.pl"; //microsoft cert validation is OK

        [TestMethod]
        public void TestVerifyTimestampSimple()
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

            TimestampVerifier verifier = new TimestampVerifier();
            TimestampObject verifiedTimestamp = verifier.SetTimestampedData(data)
                .SetHashAlgorithm(HashAlgorithm.SHA1)
                .SetTimestamp(timestamp.Timestamp)
                .Verify();
        }

        [TestMethod]
        public void TestVerifyTimestampUsingConfiguration()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);

            TimestampCreator creator = new TimestampCreator();
            TimestampObject timestamp = creator
                .SetDataForTimestamping(data)
                .CreateTimestamp();

            Assert.AreEqual(HashAlgorithm.SHA1, timestamp.HashAlgorithm);

            TimestampVerifier verifier = new TimestampVerifier();
            TimestampObject verifiedTimestamp = verifier.SetTimestampedData(data)
                .SetTimestamp(timestamp.Timestamp)
                .Verify();
        }

        [TestMethod]
        public void TestVerifyTimestampFromDigest()
        {
            byte[] digest = new System.Security.Cryptography.SHA1Cng().ComputeHash(Encoding.UTF8.GetBytes(dataToTimestamp));

            TimestampCreator creator = new TimestampCreator();
            TimestampObject timestamp = creator
                .SetTsaPrimaryUrl(tsaUrl2)
                .SetHashAlgorithm(HashAlgorithm.SHA1)
                .SetOutputFormat(OutputFormat.TSR)
                .SetMessageDigestForTimestamping(digest)
                .CreateTimestamp();

            TimestampVerifier verifier = new TimestampVerifier();
            TimestampObject verifiedTimestamp = verifier.SetMessageDigest(digest)
                .SetHashAlgorithm(HashAlgorithm.SHA1)
                .SetTimestamp(timestamp.Timestamp)
                .Verify();
        }

        [TestMethod]
        [ExpectedException(typeof(TspValidationException))]
        public void TestVerifyWrongTimestampData()
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

            data = Encoding.UTF8.GetBytes("Other string");

            TimestampVerifier verifier = new TimestampVerifier();
            verifier.SetTimestampedData(data)
            .SetHashAlgorithm(HashAlgorithm.SHA1)
            .SetTimestamp(timestamp.Timestamp)
            .Verify();
        }

        [TestMethod]
        [ExpectedException(typeof(TimestampException))]
        public void TestVerifyWrongTimestamp()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);
            TimestampVerifier verifier = new TimestampVerifier();
            verifier.SetTimestamp(data);

        }

        [TestMethod]
        public void TestIsValidAfterRevocation()
        {
            ISignatureFactory signatureFactory = TestUtils.GetSignatureFactory();
            X509Certificate certificate = TestUtils.GenerateCertificate(signatureFactory);
            X509Crl crl = TestUtils.GenerateCrl(certificate, signatureFactory, CrlReason.AffiliationChanged);

            Assert.IsTrue(TestUtils.IsValidAfterRevocationFake(crl, certificate, DateTime.Now.AddDays(-10)));
            Assert.IsFalse(TestUtils.IsValidAfterRevocationFake(crl, certificate, DateTime.Now.AddDays(10)));

            crl = TestUtils.GenerateCrl(certificate, signatureFactory, CrlReason.CACompromise);

            Assert.IsFalse(TestUtils.IsValidAfterRevocationFake(crl, certificate, DateTime.Now.AddDays(-10)));
            Assert.IsFalse(TestUtils.IsValidAfterRevocationFake(crl, certificate, DateTime.Now.AddDays(10)));
        }        
    }
}
