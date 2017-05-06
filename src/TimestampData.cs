using Org.BouncyCastle.Tsp;
using System;
using System.IO;

namespace AbsoluteTimestamp
{
    /// <summary>
    /// This class serves as a container for data that is going to be timestamped.
    /// It can hold one or more files which it can be provided as string, stream or byte array.
    /// This class can also hash this data with appropriate hash algorithm. Or it can hold already hashed message digest.
    /// </summary>
    internal class TimestampData
    {
        private string pathToFile;
        private string[] pathsToFiles;
        private Stream stream;
        private Stream[] streams;
        private byte[] data;
        private byte[][] datas;
        private byte[] digest;
        private byte[][] digests;

        private DataMode mode;

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampData"/> class.
        /// </summary>
        /// <param name="path">Path to file.</param>
        public TimestampData(string path)
        {
            pathToFile = path;
            mode = DataMode.PATH_1;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampData"/> class.
        /// </summary>
        /// <param name="paths">Paths to files.</param>
        public TimestampData(string[] paths)
        {
            pathsToFiles = paths;
            mode = DataMode.PATH_N;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampData"/> class.
        /// </summary>
        /// <param name="s">Stream.</param>
        public TimestampData(Stream s)
        {
            stream = s;
            mode = DataMode.STREAM_1;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampData"/> class.
        /// </summary>
        /// <param name="s">Streams.</param>
        public TimestampData(Stream[] s)
        {
            streams = s;
            mode = DataMode.STREAM_N;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampData"/> class.
        /// </summary>
        /// <param name="d">Byte array.</param>
        public TimestampData(byte[] d)
        {
            data = d;
            mode = DataMode.DATA_1;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampData"/> class.
        /// </summary>
        /// <param name="d">Byte arrays.</param>
        public TimestampData(byte[][] d)
        {
            datas = d;
            mode = DataMode.DATA_N;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampData"/> class.
        /// </summary>
        /// <param name="d">Byte array.</param>
        /// <param name="alreadyHashed">Flag to recognize already hashed data.</param>
        public TimestampData(byte[] d, bool alreadyHashed)
        {
            digest = d;
            mode = DataMode.HASHED_1;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TimestampData"/> class.
        /// </summary>
        /// <param name="d">Byte arrays.</param>
        /// <param name="alreadyHashed">Flag to recognize already hashed data.</param>
        public TimestampData(byte[][] d, bool alreadyHashed)
        {
            digests = d;
            mode = DataMode.HASHED_N;
        }

        #endregion

        /// <summary>
        /// Determines whether it holds multiple files.
        /// </summary>
        /// <returns>
        ///   <c>true</c> if it holds multiple files; otherwise, <c>false</c>.
        /// </returns>
        public bool HasMultipleFiles()
        {
            return 
                this.mode == DataMode.DATA_N ||
                this.mode == DataMode.STREAM_N ||
                this.mode == DataMode.PATH_N ||
                this.mode == DataMode.HASHED_N;
        }

        /// <summary>
        /// Returns data hashed with provided algorithm.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>Byte array containing hash of data.</returns>
        /// <exception cref="TimestampException">
        /// Invalid digest length for given algorithm
        /// </exception>
        public byte[] GetHashedData(HashAlgorithm hashAlgorithm)
        {
            System.Security.Cryptography.HashAlgorithm algorithm = System.Security.Cryptography.HashAlgorithm.Create(hashAlgorithm.ToString());

            switch (mode)
            {
                case DataMode.DATA_1:
                    return algorithm.ComputeHash(data);

                case DataMode.STREAM_1:
                    return algorithm.ComputeHash(stream);

                case DataMode.PATH_1:
                    try
                    {
                        return algorithm.ComputeHash(File.OpenRead(pathToFile));
                    }
                    catch (Exception e)
                    {
                        throw new TimestampException("Can't calculate message digest from file: " + pathToFile, e);
                    }                  

                case DataMode.HASHED_1:
                    if (digest.Length != hashAlgorithm.GetLength())
                    {
                        throw new TimestampException("Invalid digest length for given algorithm");
                    }
                    return digest;

                case DataMode.DATA_N:
                    for (int i = 0; i < datas.Length-1; i++)
                    {
                        algorithm.TransformBlock(datas[i], 0, datas[i].Length, datas[i], 0);
                    }
                    algorithm.TransformFinalBlock(datas[datas.Length-1], 0, datas[datas.Length-1].Length);
                    return algorithm.Hash;

                case DataMode.STREAM_N:
                    using (MemoryStream finalStream = new MemoryStream())
                    {
                        foreach (Stream stream in streams)
                        {
                            stream.CopyTo(finalStream);
                        }
                        return algorithm.ComputeHash(finalStream.ToArray());
                    }

                case DataMode.PATH_N:
                    int numberOfFiles = pathsToFiles.Length;
                    for (int i = 0; i < numberOfFiles - 1; i++)
                    {
                        try
                        {
                            byte[] currentData = File.ReadAllBytes(pathsToFiles[i]);
                            algorithm.TransformBlock(currentData, 0, currentData.Length, currentData, 0);
                        }
                        catch (Exception e)
                        {
                            throw new TimestampException("Can't calculate message digest from file: " + pathsToFiles[i], e);
                        }
                        
                    }
                    try
                    {
                        byte[] lastData = File.ReadAllBytes(pathsToFiles[numberOfFiles - 1]);
                        algorithm.TransformFinalBlock(lastData, 0, lastData.Length);
                        return algorithm.Hash;
                    }
                    catch (Exception e)
                    {
                        throw new TimestampException("Can't calculate message digest from file: " + pathsToFiles[numberOfFiles - 1], e);
                    }
                    

                case DataMode.HASHED_N:
                    int algorithmLength = hashAlgorithm.GetLength();
                    for (int i = 0; i < digests.Length - 1; i++)
                    {
                        algorithm.TransformBlock(digests[i], 0, digests[i].Length, digests[i], 0);
                    }
                    algorithm.TransformFinalBlock(digests[digests.Length - 1], 0, digests[digests.Length - 1].Length);
                    return algorithm.Hash;
            }
            return null;           
        }

        /// <summary>
        /// Only called when <see cref="TimestampCreator.outputFormat"/> is set to <see cref="OutputFormat.ASICS"/>.
        /// Returns unhashed raw data to be saved in ASICS zip file.
        /// If <see cref="HasMultipleFiles"/> then the files are ziped.
        /// </summary>
        public byte[] GetRawData()
        {
            switch (mode)
            {
                case DataMode.DATA_1:
                    return data;

                case DataMode.STREAM_1:
                    using (MemoryStream ms = new MemoryStream())
                    {
                        stream.CopyTo(ms);
                        return ms.ToArray();
                    }

                case DataMode.PATH_1:
                    return File.ReadAllBytes(pathToFile);                    

                case DataMode.HASHED_1:
                    return digest;                    

                case DataMode.DATA_N:
                    return Utils.ZipData(datas);

                case DataMode.STREAM_N:
                    byte[][] streamsAsBytes = new byte[streams.Length][];
                    for (int i = 0; i < streams.Length; i++)
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            streams[i].Position = 0;
                            streams[i].CopyTo(ms);
                            streamsAsBytes[i] = ms.ToArray();
                        }
                    }
                    return Utils.ZipData(streamsAsBytes);

                case DataMode.PATH_N:
                    byte[][] filesAsBytes = new byte[pathsToFiles.Length][];
                    for (int i = 0; i < pathsToFiles.Length; i++)
                    {
                        filesAsBytes[i] = File.ReadAllBytes(pathsToFiles[i]);
                    }
                    return Utils.ZipData(filesAsBytes);

                case DataMode.HASHED_N:
                    return Utils.ZipData(digests);
            }
            return null;
        }


        private enum DataMode
        {
            DATA_1, DATA_N, STREAM_1, STREAM_N, PATH_1, PATH_N, HASHED_1, HASHED_N
        }
    }    
}
