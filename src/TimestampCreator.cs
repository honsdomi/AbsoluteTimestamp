using Org.BouncyCastle.Tsp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AbsoluteTimestamp
{
    /// <summary>
    /// Implementation of the <see cref="ITimestampCreator"/> interface.
    /// </summary>
    public class TimestampCreator : ITimestampCreator
    {
        private string tsaPrimaryUrl;
        private NetworkCredential tsaPrimaryCredentials;
        private string tsaSecondaryUrl;
        private NetworkCredential tsaSecondaryCredentials;
        private int tsaTimeout = 0;
        private HashAlgorithm hashAlgorithm;
        private OutputFormat outputFormat;
        private TimestampData timestampData;
        private int minimumCertificateValidityPeriod = 0;

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampCreator"/> class.
        /// Also tries to load setting from configuration.
        /// </summary>
        public TimestampCreator()
        {
            this.tsaPrimaryUrl = Utils.GetConfiguration("tsa.primary.url");
            this.tsaPrimaryCredentials = new NetworkCredential(Utils.GetConfiguration("tsa.primary.username"), Utils.GetConfiguration("tsa.primary.password"));
            this.tsaSecondaryUrl = Utils.GetConfiguration("tsa.secondary.url");
            this.tsaSecondaryCredentials = new NetworkCredential(Utils.GetConfiguration("tsa.secondary.username"), Utils.GetConfiguration("tsa.secondary.password"));
            int.TryParse(Utils.GetConfiguration("tsa.timeout"), out this.tsaTimeout);
            this.hashAlgorithm = HashAlgorithmExtensions.CreateFromString(Utils.GetConfiguration("hash.algorithm"));
            this.outputFormat = OutputFormatExtensions.CreateFromString(Utils.GetConfiguration("timestamp.output"));
            int.TryParse(Utils.GetConfiguration("certificate.minimum.validity"), out this.minimumCertificateValidityPeriod);
        }

        #region Settings that can be provided by configuration file


        /// <summary>
        /// Sets the URL of primary TSA server.
        /// </summary>
        /// <param name="tsaUrl"></param>
        public ITimestampCreator SetTsaPrimaryUrl(string tsaUrl)
        {
            this.tsaPrimaryUrl = tsaUrl;
            return this;
        }


        /// <summary>
        /// Sets the credentials to access primary TSA server.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public ITimestampCreator SetTsaPrimaryCredentials(string username, string password)
        {
            this.tsaPrimaryCredentials = new NetworkCredential(username, password);
            return this;
        }

        /// <summary>
        /// Sets the URL of primary TSA server.
        /// </summary>
        /// <param name="tsaUrl"></param>
        public ITimestampCreator SetTsaSecondaryUrl(string tsaUrl)
        {
            this.tsaSecondaryUrl = tsaUrl;
            return this;
        }

        /// <summary>
        /// Sets the credentials to access primary TSA server.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public ITimestampCreator SetTsaSecondaryCredentials(string username, string password)
        {
            this.tsaSecondaryCredentials = new NetworkCredential(username, password);
            return this;
        }

        /// <summary>
        /// Sets timeout for connection to TSA.
        /// </summary>
        /// <param name="timeout">The timeout in milliseconds.</param>
        public ITimestampCreator SetTsaTimeout(int timeout)
        {
            this.tsaTimeout = timeout;
            return this;
        }

        /// <summary>
        /// Sets the hash algorithm used to hash timestamped data.
        /// </summary>
        /// <param name="hash"></param>
        public ITimestampCreator SetHashAlgorithm(HashAlgorithm hash)
        {
            this.hashAlgorithm = hash;
            return this;
        }

        /// <summary>
        /// Sets the output format for creating timestamp.
        /// </summary>
        /// <param name="format"><see cref="OutputFormat" /></param>
        public ITimestampCreator SetOutputFormat(OutputFormat format)
        {
            this.outputFormat = format;
            return this;
        }

        /// <summary>
        /// Sets the minimim certificate validity period.
        /// </summary>
        /// <param name="days"></param>
        public ITimestampCreator SetMinimimCertificateValidityPeriod(int days)
        {
            this.minimumCertificateValidityPeriod = days;
            return this;
        }

        #endregion

        #region Data from which the message digest is calculated

        /// <summary>
        /// Sets data for timestamping by providing stream.
        /// </summary>
        /// <param name="stream"></param>
        public ITimestampCreator SetDataForTimestamping(Stream stream)
        {
            this.timestampData = new TimestampData(stream);
            return this;
        }

        /// <summary>
        /// Sets data for timestamping by providing streams.
        /// </summary>
        /// <param name="streams"></param>
        public ITimestampCreator SetDataForTimestamping(Stream[] streams)
        {
            this.timestampData = new TimestampData(streams);
            return this;
        }

        /// <summary>
        /// Sets data for timestamping by providing path to file.
        /// </summary>
        /// <param name="pathToFile"></param>
        public ITimestampCreator SetDataForTimestamping(string pathToFile)
        {
            this.timestampData = new TimestampData(pathToFile);
            return this;
        }

        /// <summary>
        /// Sets data for timestamping by providing paths to files.
        /// </summary>
        /// <param name="pathsToFiles"></param>
        public ITimestampCreator SetDataForTimestamping(string[] pathsToFiles)
        {
            this.timestampData = new TimestampData(pathsToFiles);
            return this;
        }

        /// <summary>
        /// Sets data for timestamping by providing byte array.
        /// </summary>
        /// <param name="data"></param>
        public ITimestampCreator SetDataForTimestamping(byte[] data)
        {
            this.timestampData = new TimestampData(data);
            return this;
        }

        /// <summary>
        /// Sets data for timestamping by providing byte arrays.
        /// </summary>
        /// <param name="datas"></param>
        public ITimestampCreator SetDataForTimestamping(byte[][] datas)
        {
            this.timestampData = new TimestampData(datas);
            return this;
        }

        #endregion

        #region Already computed message digest

        /// <summary>
        /// Sets already hashed message to be timestamped.
        /// </summary>
        /// <param name="digest"></param>
        public ITimestampCreator SetMessageDigestForTimestamping(byte[] digest)
        {
            this.timestampData = new TimestampData(digest, true);
            return this;
        }

        /// <summary>
        /// Sets already hashed messages to be timestamped.
        /// </summary>
        /// <param name="digests"></param>
        public ITimestampCreator SetMessageDigestForTimestamping(byte[][] digests)
        {
            this.timestampData = new TimestampData(digests, true);
            return this;
        }

        #endregion

        #region Get the timestamp


        /// <summary>
        /// Creates timestamp from provided data.
        /// </summary>
        /// <returns>
        ///   <see cref="TimestampObject" />
        /// </returns>
        /// <exception cref="System.ArgumentNullException">
        /// Hash algorithm not provided.
        /// or
        /// TSA URL not provided.
        /// or
        /// Timestamp output format not provided.
        /// or
        /// Data for timestamping not provided.</exception>
        /// <exception cref="AbsoluteTimestamp.TimestampException">Cannot connect to TSA server.</exception>
        /// <exception cref="TspValidationException"></exception>
        public TimestampObject CreateTimestamp()
        {
            /* Check that everything has been provided */
            if (0 == this.hashAlgorithm)
            {
                throw new ArgumentNullException("Hash algorithm not provided.");
            }
            if (String.IsNullOrWhiteSpace(this.tsaPrimaryUrl) && String.IsNullOrWhiteSpace(this.tsaSecondaryUrl))
            {
                throw new ArgumentNullException("TSA URL not provided.");
            }
            if (0 == this.outputFormat)
            {
                throw new ArgumentNullException("Timestamp output format not provided.");
            }
            if (null == this.timestampData)
            {
                throw new ArgumentNullException("Data for timestamping not provided.");
            }

            /* Get hashed data */
            byte[] hashedData = this.timestampData.GetHashedData(this.hashAlgorithm);

            /* Generate request */
            TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.SetCertReq(true);

            TimeStampRequest request = requestGenerator.Generate(new Oid(this.hashAlgorithm.ToString()).Value, hashedData);

            /* Get response */
            TimeStampResponse response = GetTimeStampResponse(request);

            /* Validate response */
            if (!(response.Status == 0 || response.Status == 1))
            {
                throw new TspValidationException(
                    string.Format("Invalid response, response status={0}, response status string={1}, response failure info={2}",
                    response.Status, response.GetStatusString(), response.GetFailInfo().IntValue));
            }

            /*
		     * Check this response against to see if it a well formed response for
		     * the passed in request. It validates message imprint digests and message imprint algorithms.
		     *
		     * @param request the request to be checked against
		     * @throws TspException if the request can not match this response.
		     */
            response.Validate(request);

            TimeStampToken token = response.TimeStampToken;
            X509Certificate2 certificate = null;

            TimestampObject timestamp = new TimestampObject();

            /* Validate certificate */
            certificate = TimestampVerifier.ValidateCertificate(token, timestamp, minimumCertificateValidityPeriod);
            
            timestamp.HashAlgorithm = this.hashAlgorithm;            
            timestamp.Timestamp = Utils.GetTimestampForOutput(response, this.outputFormat, this.timestampData);

            return timestamp;
        }

        #endregion     
            
        private TimeStampResponse GetTimeStampResponse(TimeStampRequest request)
        {
            List<Exception> exceptions = new List<Exception>();

            /* Try primary TSA */
            try
            {
                HttpWebRequest httpRequest = CreateHttpRequest(this.tsaPrimaryUrl, this.tsaPrimaryCredentials);
                Stream requestStream = httpRequest.GetRequestStream();
                requestStream.Write(request.GetEncoded(), 0, request.GetEncoded().Length);
                return new TimeStampResponse(httpRequest.GetResponse().GetResponseStream());
            }
            catch (Exception e)
            {
                if (String.IsNullOrWhiteSpace(this.tsaSecondaryUrl))
                {
                    throw new TimestampException("Cannot connect to primary TSA server", e);
                }
                exceptions.Add(e);
            }

            /* Try secondary TSA */
            try
            {
                HttpWebRequest httpRequest = CreateHttpRequest(this.tsaSecondaryUrl, this.tsaSecondaryCredentials);
                Stream requestStream = httpRequest.GetRequestStream();
                requestStream.Write(request.GetEncoded(), 0, request.GetEncoded().Length);
                return new TimeStampResponse(httpRequest.GetResponse().GetResponseStream());
            }
            catch (Exception e)
            {
                exceptions.Add(e);
                throw new AggregateException("Cannot connect to primary or secondary TSA server", exceptions);
            }
        } 
        
        private HttpWebRequest CreateHttpRequest(string url, NetworkCredential credentials)
        {
            HttpWebRequest httpRequest = WebRequest.CreateHttp(url);
            httpRequest.Method = "POST";
            httpRequest.ContentType = "application/timestamp-query";

            if (credentials != null)
            {
                httpRequest.Credentials = credentials;
            }
            if (this.tsaTimeout != 0)
            {
                httpRequest.Timeout = this.tsaTimeout;
            }

            return httpRequest;
        }  
    }
}
