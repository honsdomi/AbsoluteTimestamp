using System;
using System.Security.Cryptography.X509Certificates;

namespace TimestampLibrary
{
    /// <summary>
    /// This class represents timestamp. 
    /// It provides useful information about the timestamp and most importantly the byte array that is needed for verification.
    /// </summary>
    public class TimestampObject
    {
        /// <summary>
        /// Time of the timestamp creation.
        /// </summary>
        public DateTime Time { get; set; }

        /// <summary>
        /// Hash algorithm used to hash timestamped data.
        /// 
        /// </summary>
        public HashAlgorithm HashAlgorithm { get; set; }

        /// <summary>
        /// Message imprint of timestamped data.
        /// </summary>
        public string MessageImprint { get; set; }

        /// <summary>
        /// TSA issuer used for timestamping this timestamp.
        /// </summary>
        public string TsaIssuer { get; set; }

        /// <summary>
        /// Certificate of TSA.
        /// </summary>
        public X509Certificate2 TsaCertificate { get; set; }

        /// <summary>
        /// Date after which the certificate is not valid.
        /// </summary>
        public DateTime TsaCertificateNotAfter
        {
            get { return this.TsaCertificate.NotAfter; }
        }

        /// <summary>
        /// Date before which the certificate is not valid.
        /// </summary>
        public DateTime TsaCertificateNotBefore
        {
            get { return this.TsaCertificate.NotBefore; }
        }

        /// <summary>
        /// Warning message for user to notice.
        /// </summary>
        public String Warning { get; set; }

        /// <summary>
        /// IMPORTANT!!!
        /// Byte representation of the timestamp. Only this field needs to be saved.
        /// </summary>
        public byte[] Timestamp { get; set; }
    }
}
