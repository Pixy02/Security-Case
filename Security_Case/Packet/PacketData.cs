using System;
using System.Collections.Generic;

namespace Packet
{
    public class Constant
    {
        public static byte[] dataBuffer = new byte[4096];
    }

    public enum Packet
    {
        SEND_KEY = 1,
        SEND_SYMMETRIC_KEY,
        SEND_MESSAGE
    }
}