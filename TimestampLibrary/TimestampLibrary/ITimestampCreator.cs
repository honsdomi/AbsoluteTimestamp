using System.IO;

namespace TimestampLibrary
{
    /// <summary>
    /// Interface for creating timestamps.
    /// 
    /// <remarks>Allow timestamping of multiple files at once.</remarks>
    /// 
    /// Typical usage:
    ///     1. (Provide settings by configuration file)
    ///     2. SetDataForTimestamping(...); or SetMessageDigestForTimestamping(...);
    ///     3. GetTimestamp();
    /// </summary>
    public interface ITimestampCreator
    {
        #region Settings that can be provided by configuration file

        /// <summary>
        /// Sets the URL of primary TSA server.
        /// </summary>
        /// <param name="tsaUrl"></param>
        ITimestampCreator SetTsaPrimaryUrl(string tsaUrl);

        /// <summary>
        /// Sets the credentials to access primary TSA server.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        ITimestampCreator SetTsaPrimaryCredentials(string username, string password);

        /// <summary>
        /// Sets the URL of secondary TSA server.
        /// </summary>
        /// <param name="tsaUrl"></param>
        ITimestampCreator SetTsaSecondaryUrl(string tsaUrl);

        /// <summary>
        /// Sets the credentials to access secondary TSA server.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        ITimestampCreator SetTsaSecondaryCredentials(string username, string password);

        /// <summary>
        /// Sets timeout for connection to TSA.
        /// </summary>
        /// <param name="timeout">The timeout in milliseconds.</param>
        ITimestampCreator SetTsaTimeout(int timeout);

        /// <summary>
        /// Sets the hash algorithm used to hash timestamped data.
        /// </summary>
        /// <param name="hash"></param>
        ITimestampCreator SetHashAlgorithm(HashAlgorithm hash);

        /// <summary>
        /// Sets the output format for creating timestamp.
        /// </summary>
        /// <param name="format"><see cref="OutputFormat"/></param>
        ITimestampCreator SetOutputFormat(OutputFormat format);

        /// <summary>
        /// Sets the minimim certificate validity period.
        /// </summary>
        /// <param name="days"></param>
        ITimestampCreator SetMinimimCertificateValidityPeriod(int days);

        #endregion

        #region Data from which the message digest is calculated

        /// <summary>
        /// Sets data for timestamping by providing path to file.
        /// </summary>
        /// <param name="pathToFile"></param>
        ITimestampCreator SetDataForTimestamping(string pathToFile);

        /// <summary>
        /// Sets data for timestamping by providing paths to files.
        /// </summary>
        /// <param name="pathsToFiles"></param>
        ITimestampCreator SetDataForTimestamping(string[] pathsToFiles);

        /// <summary>
        /// Sets data for timestamping by providing stream.
        /// </summary>
        /// <param name="stream"></param>
        ITimestampCreator SetDataForTimestamping(Stream stream);

        /// <summary>
        /// Sets data for timestamping by providing streams.
        /// </summary>
        /// <param name="streams"></param>
        ITimestampCreator SetDataForTimestamping(Stream[] streams);

        /// <summary>
        /// Sets data for timestamping by providing byte array.
        /// </summary>
        /// <param name="data"></param>
        ITimestampCreator SetDataForTimestamping(byte[] data);

        /// <summary>
        /// Sets data for timestamping by providing byte arrays.
        /// </summary>
        /// <param name="datas"></param>
        ITimestampCreator SetDataForTimestamping(byte[][] datas);

        #endregion

        #region Already computed message digest

        /// <summary>
        /// Sets already hashed message to be timestamped.
        /// </summary>
        /// <param name="digest"></param>
        ITimestampCreator SetMessageDigestForTimestamping(byte[] digest);

        /// <summary>
        /// Sets already hashed messages to be timestamped.
        /// </summary>
        /// <param name="digests"></param>
        ITimestampCreator SetMessageDigestForTimestamping(byte[][] digests);

        #endregion

        /// <summary>
        /// Creates timestamp from provided data. 
        /// </summary>
        /// <returns><see cref="TimestampObject"/></returns>
        TimestampObject CreateTimestamp();
    }
}
