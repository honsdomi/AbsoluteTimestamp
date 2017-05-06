namespace TimestampLibrary
{
    /// <summary>
    /// Specifies the output format of timestamp.
    /// </summary>
    public enum OutputFormat
    {
        /// <summary>
        /// Outputs TimestampResponse object
        /// </summary>
        TSR = 1,

        /// <summary>
        /// Outputs asics archive which contains TimestampResponse as well as timestamped files
        /// </summary>
        ASICS = 2
    }

    static class OutputFormatExtensions
    {
        public static OutputFormat CreateFromString(string format)
        {
            switch (format.ToUpper())
            {
                case "TSR":
                    return OutputFormat.TSR;

                case "ASICS":
                    return OutputFormat.ASICS;

                default:
                    return 0;
            }
        }
    }
}
