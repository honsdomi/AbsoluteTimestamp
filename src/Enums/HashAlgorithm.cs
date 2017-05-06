using System.Collections.Generic;

namespace AbsoluteTimestamp
{
    /// <summary>
    /// Hash algorithms that can be used for timestamping.
    /// </summary>
    public enum HashAlgorithm
    {
        /// <summary>
        /// MD5 algorithm. Length = 16 bytes
        /// </summary>
        MD5 = 1,

        /// <summary>
        /// SHA1 algorithm. Length = 20 bytes
        /// </summary>
        SHA1 = 2,

        /// <summary>
        /// SHA256 algorithm. Length = 32 bytes
        /// </summary>
        SHA256 = 3,

        /// <summary>
        /// SHA512 algorithm. Length = 64 bytes
        /// </summary>
        SHA512 = 4
    }

    /// <summary>
    /// This class provides validation of hash algorithm length.
    /// </summary>
    static class HashAlgorithmExtensions
    {
        private static readonly Dictionary<HashAlgorithm, int> algorithms;

        static HashAlgorithmExtensions()
        {
            algorithms = new Dictionary<HashAlgorithm, int>();
            algorithms.Add(HashAlgorithm.MD5, 16);
            algorithms.Add(HashAlgorithm.SHA1, 20);
            algorithms.Add(HashAlgorithm.SHA256, 32);
            algorithms.Add(HashAlgorithm.SHA512, 64);
        }
        
        /// <summary>
        /// Returns length of hash algorithm output.
        /// </summary>
        /// <returns>Lenght of output from given algorithm</returns>
        public static int GetLength(this HashAlgorithm hash)
        {
            return algorithms[hash];
        }
        
        public static HashAlgorithm CreateFromString(string name)
        {
            switch (name.ToUpper())
            {
                case "MD5":
                    return HashAlgorithm.MD5;

                case "SHA1":
                    return HashAlgorithm.SHA1;

                case "SHA256":
                    return HashAlgorithm.SHA256;

                case "SHA512":
                    return HashAlgorithm.SHA512;

                default:
                    return 0;
            }
        }        
    }
}
