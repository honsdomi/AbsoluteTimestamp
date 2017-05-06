using Microsoft.VisualStudio.TestTools.UnitTesting;
using AbsoluteTimestamp;
using System;
using System.Text;
using System.Linq;
using System.IO;

namespace TimestampLibraryTests
{
    [TestClass]
    public class TimestampDataTest
    {
        private const string dataToTimestamp = "Test string to timestamp.";
        private const string dataToTimestamp2 = "Other string to timestamp.";

        #region Byte array tests

        [TestMethod]
        public void TestGetHashFromByteArray()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);
            TimestampData timestampData = new TimestampData(data);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);
            byte[] expectedResult = new System.Security.Cryptography.SHA1Cng().ComputeHash(data);

            Assert.IsTrue(result.SequenceEqual(expectedResult));
        }

        [TestMethod]
        public void TestGetHashFromByteArrays()
        {
            byte[][] datas = {
                Encoding.UTF8.GetBytes(dataToTimestamp),
                Encoding.UTF8.GetBytes(dataToTimestamp2)};
            TimestampData timestampData = new TimestampData(datas);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);

            System.Security.Cryptography.HashAlgorithm algorithm = new System.Security.Cryptography.SHA1Cng();
            for (int i = 0; i < datas.Length - 1; i++)
            {
                algorithm.TransformBlock(datas[i], 0, datas[i].Length, datas[i], 0);
            }
            algorithm.TransformFinalBlock(datas[datas.Length - 1], 0, datas[datas.Length - 1].Length);
            byte[] expectedResult = algorithm.Hash;

            Assert.IsTrue(result.SequenceEqual(expectedResult));
        }

        [TestMethod]
        public void TestGetHashFromByteArraysWrongOrder()
        {
            byte[][] datas = {
                Encoding.UTF8.GetBytes(dataToTimestamp),
                Encoding.UTF8.GetBytes(dataToTimestamp2)};
            TimestampData timestampData = new TimestampData(datas);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);

            System.Security.Cryptography.HashAlgorithm algorithm = new System.Security.Cryptography.SHA1Cng();
            for (int i = datas.Length - 1; i >= 1; i--)
            {
                algorithm.TransformBlock(datas[i], 0, datas[i].Length, datas[i], 0);
            }
            algorithm.TransformFinalBlock(datas[0], 0, datas[0].Length);
            byte[] expectedResult = algorithm.Hash; ;

            Assert.IsFalse(result.SequenceEqual(expectedResult));
        }

        [TestMethod]
        public void TestGetHashFromByteArraysRepeatableResults()
        {
            byte[][] datas = {
                Encoding.UTF8.GetBytes(dataToTimestamp),
                Encoding.UTF8.GetBytes(dataToTimestamp2)};
            TimestampData timestampData = new TimestampData(datas);
            byte[] result1 = timestampData.GetHashedData(HashAlgorithm.SHA1);
            byte[] result2 = timestampData.GetHashedData(HashAlgorithm.SHA1);
            byte[] result3 = timestampData.GetHashedData(HashAlgorithm.SHA1);

            Assert.IsTrue(result1.SequenceEqual(result2));
            Assert.IsTrue(result1.SequenceEqual(result3));
            Assert.IsTrue(result2.SequenceEqual(result3));
        }

        [TestMethod]
        public void TestGetHashFromByteArrayVsArrays()
        {
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);
            TimestampData timestampData1 = new TimestampData(data);
            byte[] result1 = timestampData1.GetHashedData(HashAlgorithm.SHA1);

            byte[][] datas = {
                Encoding.UTF8.GetBytes(dataToTimestamp),
                Encoding.UTF8.GetBytes(dataToTimestamp2)};
            TimestampData timestampData2 = new TimestampData(datas);
            byte[] result2 = timestampData2.GetHashedData(HashAlgorithm.SHA1);

            Assert.IsFalse(result1.SequenceEqual(result2));
        }

        #endregion

        #region Stream tests

        [TestMethod]
        public void TestGetHashFromStream()
        {
            Stream stream = new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp));
            TimestampData timestampData = new TimestampData(stream);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);

            stream = new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp));
            byte[] expectedResult = new System.Security.Cryptography.SHA1Cng().ComputeHash(stream);

            Assert.IsTrue(result.SequenceEqual(expectedResult));
        }

        [TestMethod]
        public void TestGetHashFromStreamRepeatedly()
        {
            Stream stream = new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp));
            TimestampData timestampData = new TimestampData(stream);
            byte[] result1 = timestampData.GetHashedData(HashAlgorithm.SHA1);

            stream = new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp));
            timestampData = new TimestampData(stream);
            byte[] result2 = timestampData.GetHashedData(HashAlgorithm.SHA1);

            Assert.IsTrue(result1.SequenceEqual(result2));
        }

        [TestMethod]
        public void TestGetHashFromStreams()
        {
            Stream[] streams = {
                new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp)),
                new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp2)) };
            TimestampData timestampData = new TimestampData(streams);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);

            Stream[] streams2 = {
                new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp)),
                new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp2)) };
            System.Security.Cryptography.HashAlgorithm algorithm = new System.Security.Cryptography.SHA1Cng();
            using (MemoryStream finalStream = new MemoryStream())
            {
                foreach (Stream stream in streams2)
                {
                    stream.CopyTo(finalStream);
                }
                byte[] expectedResult = algorithm.ComputeHash(finalStream.ToArray());

                Assert.IsTrue(result.SequenceEqual(expectedResult));
            }
        }

        [TestMethod]
        public void TestGetHashFromStreamsWrongOrder()
        {
            Stream[] streams1 = {
                new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp)),
                new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp2)) };
            TimestampData timestampData1 = new TimestampData(streams1);
            byte[] result1 = timestampData1.GetHashedData(HashAlgorithm.SHA1);

            Stream[] streams2 = {
                new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp2)),
                new MemoryStream(Encoding.UTF8.GetBytes(dataToTimestamp)) };
            TimestampData timestampData2 = new TimestampData(streams2);
            byte[] result2 = timestampData2.GetHashedData(HashAlgorithm.SHA1);

            Assert.IsFalse(result1.SequenceEqual(result2));
        }

        #endregion

        #region Path tests

        [TestMethod]
        public void TestGetHashFromPath()
        {
            string path = Path.Combine(Environment.CurrentDirectory, "test.txt");
            File.WriteAllText(path, dataToTimestamp);

            TimestampData timestampData = new TimestampData(path);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);
            byte[] data = Encoding.UTF8.GetBytes(dataToTimestamp);
            byte[] expectedResult = new System.Security.Cryptography.SHA1Cng().ComputeHash(data);

            Assert.IsTrue(result.SequenceEqual(expectedResult));
        }

        [TestMethod]
        [ExpectedException(typeof(TimestampException))]
        public void TestGetHashFromWrongPath()
        {
            string path = "C:\\InvalidPath";
            TimestampData timestampData = new TimestampData(path);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);
        }

        [TestMethod]
        public void TestGetHashFromPaths()
        {
            string path1 = Path.Combine(Environment.CurrentDirectory, "test1.txt");
            File.WriteAllText(path1, dataToTimestamp);
            string path2 = Path.Combine(Environment.CurrentDirectory, "test2.txt");
            File.WriteAllText(path2, dataToTimestamp2);

            string[] paths = { path1, path2 };

            TimestampData timestampData = new TimestampData(paths);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);

            byte[][] datas = {
                Encoding.UTF8.GetBytes(dataToTimestamp),
                Encoding.UTF8.GetBytes(dataToTimestamp2)};

            System.Security.Cryptography.HashAlgorithm algorithm = new System.Security.Cryptography.SHA1Cng();
            for (int i = 0; i < datas.Length - 1; i++)
            {
                algorithm.TransformBlock(datas[i], 0, datas[i].Length, datas[i], 0);
            }
            algorithm.TransformFinalBlock(datas[datas.Length - 1], 0, datas[datas.Length - 1].Length);
            byte[] expectedResult = algorithm.Hash;

            Assert.IsTrue(result.SequenceEqual(expectedResult));
        }

        [TestMethod]
        [ExpectedException(typeof(TimestampException))]
        public void TestGetHashFromWrongPaths()
        {
            string path1 = Path.Combine(Environment.CurrentDirectory, "test1.txt");
            File.WriteAllText(path1, dataToTimestamp);
            string path2 = Path.Combine(Environment.CurrentDirectory, "test2.txt");
            File.WriteAllText(path2, dataToTimestamp2);

            string[] paths = { path1, path2, "InvalidPath" };

            TimestampData timestampData = new TimestampData(paths);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);
        }

        #endregion

        #region Digest tests

        [TestMethod]
        public void TestGetHashFromDigest()
        {
            byte[] digest = new System.Security.Cryptography.SHA1Cng().ComputeHash(Encoding.UTF8.GetBytes(dataToTimestamp));
            TimestampData timestampData = new TimestampData(digest, true);
            byte[] result = timestampData.GetHashedData(HashAlgorithm.SHA1);

            Assert.IsTrue(result.SequenceEqual(digest));
        }

        [TestMethod]
        [ExpectedException(typeof(TimestampException))]
        public void TestGetHashFromDigestWrongAlgorithm()
        {
            byte[] digest = new System.Security.Cryptography.SHA1Cng().ComputeHash(Encoding.UTF8.GetBytes(dataToTimestamp));
            TimestampData timestampData = new TimestampData(digest, true);

            byte[] result = timestampData.GetHashedData(HashAlgorithm.MD5);
        }

        #endregion
    }
}
