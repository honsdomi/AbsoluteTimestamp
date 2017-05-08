using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Text.RegularExpressions;
using System.Net;
using Org.BouncyCastle.Asn1;

namespace AbsoluteTimestamp
{
    /// <summary>
    /// Implementation of the <see cref="ITimestampVerifier" /> interface.
    /// </summary>
    public class TimestampVerifier : ITimestampVerifier
    {
        private TimestampData timestampData;
        private TimeStampResponse timestampResponse;
        private HashAlgorithm hashAlgorithm;
        private int minimumCertificateValidityPeriod = 0;

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampVerifier"/> class.
        /// Also tries to load settings from configuration.
        /// </summary>
        public TimestampVerifier()
        {
            this.hashAlgorithm = HashAlgorithmExtensions.CreateFromString(Utils.GetConfiguration("hash.algorithm"));
            int.TryParse(Utils.GetConfiguration("certificate.minimum.validity"), out this.minimumCertificateValidityPeriod);
        }


        #region Data from which the message digest was calculated

        /// <summary>
        /// Sets the timestamped data by providing stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestampedData(Stream stream)
        {
            this.timestampData = new TimestampData(stream);
            return this;
        }

        /// <summary>
        /// Sets the timestamped data by providing streams.
        /// </summary>
        /// <param name="streams">The streams.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestampedData(Stream[] streams)
        {
            this.timestampData = new TimestampData(streams);
            return this;
        }

        /// <summary>
        /// Sets the timestamped data by providing byte array.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestampedData(byte[] data)
        {
            this.timestampData = new TimestampData(data);
            return this;
        }

        /// <summary>
        /// Sets the timestamped data by providing byte arrays.
        /// </summary>
        /// <param name="datas">The datas.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestampedData(byte[][] datas)
        {
            this.timestampData = new TimestampData(datas);
            return this;
        }

        /// <summary>
        /// Sets the timestamped data by providing path to file.
        /// </summary>
        /// <param name="pathToFile">The path to file.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestampedData(string pathToFile)
        {
            this.timestampData = new TimestampData(pathToFile);
            return this;
        }

        /// <summary>
        /// Sets the timestamped data by providing paths to files.
        /// </summary>
        /// <param name="pathsToFiles">The paths to files.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestampedData(string[] pathsToFiles)
        {
            this.timestampData = new TimestampData(pathsToFiles);
            return this;
        }

        /// <summary>
        /// Sets the hash algorithm used to create the timestamp.
        /// </summary>
        /// <param name="hash">The hash algorithm.</param>
        /// <returns></returns>
        public ITimestampVerifier SetHashAlgorithm(HashAlgorithm hash)
        {
            this.hashAlgorithm = hash;
            return this;
        }

        /// <summary>
        /// Sets the minimim certificate validity period.
        /// </summary>
        /// <param name="days"></param>
        public ITimestampVerifier SetMinimimCertificateValidityPeriod(int days)
        {
            this.minimumCertificateValidityPeriod = days;
            return this;
        }

        #endregion

        #region Already computed message digest

        /// <summary>
        /// Sets already hashed message.
        /// </summary>
        /// <param name="digest">The digest.</param>
        /// <returns></returns>
        public ITimestampVerifier SetMessageDigest(byte[] digest)
        {
            this.timestampData = new TimestampData(digest, true);
            return this;
        }

        /// <summary>
        /// Sets already hashed messages.
        /// </summary>
        /// <param name="digests">The digests.</param>
        /// <returns></returns>
        public ITimestampVerifier SetMessageDigest(byte[][] digests)
        {
            this.timestampData = new TimestampData(digests, true);
            return this;
        }

        #endregion

        #region Provide the actual timestamp

        /// <summary>
        /// Sets the timestamp by providing stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestamp(Stream stream)
        {
            try
            {
                this.timestampResponse = new TimeStampResponse(stream);
                return this;
            }
            catch (Exception e)
            {
                throw new TimestampException("Can't load Timestamp", e);
            }

        }

        /// <summary>
        /// Sets the timestamp by providing byte array.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestamp(byte[] data)
        {
            try
            {
                this.timestampResponse = new TimeStampResponse(data);
                return this;
            }
            catch (Exception e)
            {
                throw new TimestampException("Can't load Timestamp", e);
            }
        }

        /// <summary>
        /// Sets the timestamp by providing path to file.
        /// </summary>
        /// <param name="pathToFile">The path to file.</param>
        /// <returns></returns>
        public ITimestampVerifier SetTimestamp(string pathToFile)
        {
            try
            {
                this.timestampResponse = new TimeStampResponse(File.OpenRead(pathToFile));
                return this;
            }
            catch (Exception e)
            {
                throw new TimestampException("Can't load Timestamp", e);
            }
        }

        #endregion

        /// <summary>
        /// Verifies that timestamp is valid.
        /// </summary>
        /// <returns>
        ///   <see cref="TimestampObject" />
        /// </returns>
        /// <exception cref="System.ArgumentNullException">
        /// Hash algorithm not provided.
        /// or
        /// Data for timestamping not provided.
        /// </exception>
        public TimestampObject Verify()
        {
            /* Check that everything has been provided */
            if (0 == this.hashAlgorithm)
            {
                throw new ArgumentNullException("Hash algorithm not provided.");
            }
            if (null == this.timestampData)
            {
                throw new ArgumentNullException("Data for timestamping not provided.");
            }
            if (null == this.timestampResponse)
            {
                throw new ArgumentNullException("Timestamp not provided.");
            }

            /* Get hashed data */
            byte[] hashedData = timestampData.GetHashedData(this.hashAlgorithm);

            /* Generate request */
            TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();

            TimeStampRequest request = requestGenerator.Generate(new Oid(this.hashAlgorithm.ToString()).Value, hashedData);

            /*
		     * Check this response against to see if it a well formed response for
		     * the passed in request. It validates message imprint digests and message imprint algorithms.
		     *
		     * @param request the request to be checked against
		     * @throws TspException if the request can not match this response.
		     */
            this.timestampResponse.Validate(request);

            TimeStampToken token = timestampResponse.TimeStampToken;
            TimestampObject timestamp = new TimestampObject();

            /* Validate certificate */
            X509Certificate2 certificate = ValidateCertificate(token, timestamp, minimumCertificateValidityPeriod);

            timestamp.HashAlgorithm = this.hashAlgorithm;
            timestamp.Timestamp = this.timestampResponse.GetEncoded();

            return timestamp;
        }

        /// <summary>
        /// Extracts and validates the certificate from token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <param name="validityPeriod">Required certificate validity</param>
        /// <returns><see cref="X509Certificate2" /></returns>
        /// <exception cref="TspValidationException">Invalid response, more than one certificate found</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Certificate chain validation failed.</exception>
        public static X509Certificate2 ValidateCertificate(TimeStampToken token, TimestampObject timestamp, int validityPeriod)
        {
            X509Certificate2 tsaCertificate = null;
            SignerID signer = token.SignerID;

            ICollection certificates = token.GetCertificates("Collection").GetMatches(signer);
            if (certificates.Count > 1)
            {
                throw new TspValidationException("Invalid response, more than one certificate found");
            }
            foreach (Org.BouncyCastle.X509.X509Certificate cert in certificates)
            {
                /*
                 * Validate the time stamp token.
                 * <p>
                 * To be valid the token must be signed by the passed in certificate and
                 * the certificate must be the one referred to by the SigningCertificate
                 * attribute included in the hashed attributes of the token. The
                 * certificate must also have the ExtendedKeyUsageExtension with only
                 * KeyPurposeID.IdKPTimeStamping and have been valid at the time the
                 * timestamp was created.
                 * </p>
                 * <p>
                 * A successful call to validate means all the above are true.
                 * </p>
                 */
                token.Validate(cert);

                /// <summary>
                /// Return true if the nominated time is within the start and end times nominated on the certificate.
                /// </summary>
                /// <param name="time">The time to test validity against.</param>
                /// <returns>True if certificate is valid for nominated time.</returns>
                if (!cert.IsValid(token.TimeStampInfo.GenTime))
                {
                    throw new TspValidationException("Certificate is not valid at the time of timestamp creation.");
                }

                /* Set warning if signing certificate is expired or is about to expire */
                if (!cert.IsValidNow)
                {
                    timestamp.Warning = "Signing certificate expired.";
                }
                else if (validityPeriod > 0)
                {
                    int expireDays = (cert.NotAfter - DateTime.Now).Days;
                    if (expireDays <= validityPeriod)
                    {
                        timestamp.Warning = string.Format("Signing certificate is going to expire in {0} days on {1}.", expireDays, cert.NotAfter);
                    }
                }

                /*
		        * verify that the given certificate successfully handles and confirms
		        * the signature associated with this signer and, if a signingTime
		        * attribute is available, that the certificate was valid at the time the
		        * signature was generated.
		        */
                token.ToCmsSignedData().GetSignerInfos().GetFirstSigner(signer).Verify(cert);

                tsaCertificate = new X509Certificate2(cert.GetEncoded());

                /* Microsoft validation */
                X509Chain chain = new X509Chain();
                chain.ChainPolicy.VerificationTime = token.TimeStampInfo.GenTime;

                if (!chain.Build(tsaCertificate))
                {
                    /* Search for revoked certificate */
                    bool allRevokedCertificatesAreValid = true;
                    foreach (X509ChainElement element in chain.ChainElements)
                    {
                        if (IsRevoked(element) && !IsValidAfterRevocation(element.Certificate, token.TimeStampInfo.GenTime))
                        {
                            allRevokedCertificatesAreValid = false;
                            break;
                        }
                    }

                    string failReason = "";
                    foreach (X509ChainStatus status in chain.ChainStatus)
                    {
                        if (status.Status != X509ChainStatusFlags.Revoked || !allRevokedCertificatesAreValid)
                        {
                            failReason += status.Status + ": " + status.StatusInformation;
                        }

                    }
                    if (failReason != "")
                    {
                        throw new CryptographicException("Certificate chain validation failed.\n" + failReason);
                    }
                }
            }

            timestamp.Time = token.TimeStampInfo.GenTime;
            timestamp.TsaIssuer = token.SignerID.Issuer.ToString();
            timestamp.TsaCertificate = tsaCertificate;
            timestamp.MessageImprint = BitConverter.ToString(token.TimeStampInfo.TstInfo.MessageImprint.GetHashedMessage());
            return tsaCertificate;
        }

        /// <summary>
        /// Determines whether timestamp, signed by given certificate, can be considered valid, even after said certificate has been revoked.
        /// It follows rules discribed in RFC3161 section 4.1.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="timestampGenTime">The timestamp time.</param>
        /// <returns>
        ///   <c>true</c> if [is valid after revocation] [the specified certificate]; otherwise, <c>false</c>.
        /// </returns>
        private static bool IsValidAfterRevocation(X509Certificate2 certificate, DateTime timestampGenTime)
        {
            try
            {
                /* Get CRL url from certificate */
                Org.BouncyCastle.X509.X509Certificate cert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(certificate);
                X509Extension revocationExtension = (from X509Extension extension in certificate.Extensions where extension.Oid.Value.Equals("2.5.29.31") select extension).Single();
                Regex rx = new Regex("http://.*?\\.crl");
                foreach (Match match in rx.Matches(new AsnEncodedData(revocationExtension.Oid, revocationExtension.RawData).Format(false)))
                {
                    string crlUrl = match.Value;
                    WebClient client = new WebClient();

                    X509CrlParser crlParser = new X509CrlParser();
                    X509Crl crl = crlParser.ReadCrl(client.DownloadData(crlUrl));

                    if (crl.IsRevoked(cert))
                    {
                        X509CrlEntry revokedEntry = crl.GetRevokedCertificate(cert.SerialNumber);
                        DateTime revocationDate = revokedEntry.RevocationDate;

                        /* All timestamps created after revocation date are invalid */
                        if (DateTime.Compare(timestampGenTime, revocationDate) > 0)
                        {
                            return false;
                        }

                        DerEnumerated reasonCode = DerEnumerated.GetInstance(GetExtensionValue(revokedEntry, Org.BouncyCastle.Asn1.X509.X509Extensions.ReasonCode));

                        /* If the revocation reason is not present, the timestamp is considered invalid */
                        if (reasonCode == null)
                        {
                            return false;
                        }

                        int reason = reasonCode.Value.IntValue;

                        /* If the revocation reason is any other value, the timestamp is considered invalid */
                        if (!(reason == Org.BouncyCastle.Asn1.X509.CrlReason.Unspecified ||
                            reason == Org.BouncyCastle.Asn1.X509.CrlReason.AffiliationChanged ||
                            reason == Org.BouncyCastle.Asn1.X509.CrlReason.Superseded ||
                            reason == Org.BouncyCastle.Asn1.X509.CrlReason.CessationOfOperation))
                        {
                            return false;
                        }
                    }
                }
            }
            catch
            {
                return false;
            }
            return true;
        }

        /// <summary>
		/// Extract the value of the given extension, if it exists.
		/// </summary>
		/// <param name="ext">The extension object.</param>
		/// <param name="oid">The object identifier to obtain.</param>
		/// <returns>Asn1Object</returns>
		/// <exception cref="Exception">if the extension cannot be read.</exception>
		private static Asn1Object GetExtensionValue(IX509Extension ext, DerObjectIdentifier oid)
        {
            Asn1OctetString bytes = ext.GetExtensionValue(oid);

            if (bytes == null)
                return null;

            return Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(bytes);
        }

        /// <summary>
        /// Determines whether the specified element contains status Revoked.
        /// </summary>
        /// <param name="element">The chain element.</param>
        /// <returns>
        ///   <c>true</c> if the specified element is revoked; otherwise, <c>false</c>.
        /// </returns>
        private static bool IsRevoked(X509ChainElement element)
        {
            return Array.IndexOf(element.ChainElementStatus, X509ChainStatusFlags.Revoked) > -1;
        }
    }
}
