using System.IO;

namespace TimestampLibrary
{
    /// <summary>
    /// Interface for verifying validity of timestamps.
    /// 
    /// Typical usage:
    ///     1. SetTimestampedData(); or SetMessageDigest();
    ///     2. SetTimestamp();
    ///     3. Verify();
    /// </summary>
    public interface ITimestampVerifier
    {
        #region Data from which the message digest was calculated   
             
        /// <summary>
        /// Sets the timestamped data by providing path to file.
        /// </summary>
        /// <param name="pathToFile">The path to file.</param>
        ITimestampVerifier SetTimestampedData(string pathToFile);

        /// <summary>
        /// Sets the timestamped data by providing paths to files.
        /// </summary>
        /// <param name="pathsToFiles">The paths to files.</param>
        ITimestampVerifier SetTimestampedData(string[] pathsToFiles);

        /// <summary>
        /// Sets the timestamped data by providing stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        ITimestampVerifier SetTimestampedData(Stream stream);

        /// <summary>
        /// Sets the timestamped data by providing streams.
        /// </summary>
        /// <param name="streams">The streams.</param>
        ITimestampVerifier SetTimestampedData(Stream[] streams);

        /// <summary>
        /// Sets the timestamped data by providing byte array.
        /// </summary>
        /// <param name="data">The data.</param>
        ITimestampVerifier SetTimestampedData(byte[] data);

        /// <summary>
        /// Sets the timestamped data by providing byte arrays.
        /// </summary>
        /// <param name="datas">The datas.</param>
        ITimestampVerifier SetTimestampedData(byte[][] datas);

        #endregion

        #region Already computed message digest        

        /// <summary>
        /// Sets already hashed message.
        /// </summary>
        /// <param name="digest">The digest.</param>
        ITimestampVerifier SetMessageDigest(byte[] digest);

        /// <summary>
        /// Sets already hashed messages.
        /// </summary>
        /// <param name="digests">The digests.</param>
        ITimestampVerifier SetMessageDigest(byte[][] digests);

        #endregion

        #region Provide the actual timestamp

        /// <summary>
        /// Sets the timestamp by providing path to file.
        /// </summary>
        /// <param name="pathToFile">The path to file.</param>
        ITimestampVerifier SetTimestamp(string pathToFile);

        /// <summary>
        /// Sets the timestamp by providing byte array.
        /// </summary>
        /// <param name="data">The data.</param>
        ITimestampVerifier SetTimestamp(byte[] data);

        /// <summary>
        /// Sets the timestamp by providing stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        ITimestampVerifier SetTimestamp(Stream stream);

        #endregion

        /// <summary>
        /// Sets the hash algorithm used to create the timestamp.
        /// </summary>
        /// <param name="hash">The hash algorithm.</param>
        ITimestampVerifier SetHashAlgorithm(HashAlgorithm hash);

        /// <summary>
        /// Sets the minimim certificate validity period.
        /// </summary>
        /// <param name="days"></param>
        ITimestampVerifier SetMinimimCertificateValidityPeriod(int days);

        /// <summary>
        /// Verifies that timestamp is valid.
        /// </summary>
        /// <returns><see cref="TimestampObject"/></returns>
        TimestampObject Verify();
    }
}
