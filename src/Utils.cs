using System.IO;
using System.IO.Compression;
using System.Text;
using System.Reflection;
using System.Collections.Generic;
using Org.BouncyCastle.Tsp;
using System;

namespace AbsoluteTimestamp
{
    internal static class Utils
    {     
        private static Dictionary<string, string> configuration; 

        static Utils()
        {
            try
            {
                Assembly _assembly = Assembly.GetExecutingAssembly();
                StreamReader _configurationReader = new StreamReader(_assembly.GetManifestResourceStream("AbsoluteTimestamp.configuration.txt"));

                configuration = new Dictionary<string, string>();

                string line;

                while ((line = _configurationReader.ReadLine()) != null)
                {
                    string[] split = line.Split('=');
                    configuration.Add(split[0], split[1]);
                }
            }
            catch(Exception e)
            {
                throw new TimestampException("Error accessing configuration file.", e);
            }
        }

        public static string GetConfiguration(string key)
        {
            if (configuration.ContainsKey(key))
            {
                return configuration[key];
            }
            return null;
        }

        public static byte[] GetAsics(byte[] response, byte[] timestampData, bool dataIsZipped)
        {
            MemoryStream zipContent = new MemoryStream();
            ZipArchive zipArchive = new ZipArchive(zipContent, ZipArchiveMode.Create);

            AddEntryToZip(zipArchive, "mimetype", Encoding.UTF8.GetBytes("application/vnd.etsi.asic-s+zip"));
            AddEntryToZip(zipArchive, "META-INF/timestamp.tsr", response);
            string dataName = dataIsZipped ? "data.zip" : "data";
            AddEntryToZip(zipArchive, dataName, timestampData);

            zipArchive.Dispose();
            return zipContent.ToArray();
        }

        public static byte[] ZipData(byte[][] timestampData)
        {
            MemoryStream zipContent = new MemoryStream();
            ZipArchive zipArchive = new ZipArchive(zipContent, ZipArchiveMode.Create);

            for (int i = 0; i < timestampData.Length; i++)
            {
                AddEntryToZip(zipArchive, "data" + (i + 1), timestampData[i]);
            }           

            zipArchive.Dispose();
            return zipContent.ToArray();
        }

        private static void AddEntryToZip(ZipArchive archive, string entryName, byte[] entryContent)
        {
            ZipArchiveEntry entry = archive.CreateEntry(entryName);
            using (Stream stream = entry.Open())
                stream.Write(entryContent, 0, entryContent.Length);
        }

        public static byte[] GetTimestampForOutput(TimeStampResponse response, OutputFormat outputFormat, TimestampData timestampData)
        {
            switch (outputFormat)
            {
                case OutputFormat.TSR:
                    return response.GetEncoded();

                case OutputFormat.ASICS:
                    return Utils.GetAsics(response.GetEncoded(), timestampData.GetRawData(), timestampData.HasMultipleFiles());

            }
            return null;
        }
    }
}
