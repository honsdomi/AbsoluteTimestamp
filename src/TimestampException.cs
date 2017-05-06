using System;

namespace AbsoluteTimestamp
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="System.Exception" />
    public class TimestampException : Exception
    {
        public TimestampException()
        {
        }

        public TimestampException(string message)
        : base(message)
        {
        }

        public TimestampException(string message, Exception inner)
        : base(message, inner)
        {
        }
    }
}
