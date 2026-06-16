using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace StraitJacket
{
    // Minimal DNS client that queries public resolvers directly over UDP.
    // We must bypass the OS resolver because the hosts file already maps the
    // blocked domains to 0.0.0.0 -- so System.Net.Dns would just return that.
    // This gives us the *real* IPs to feed into the firewall layer.
    static class DnsResolver
    {
        static readonly string[] Resolvers = { "1.1.1.1", "8.8.8.8" };
        const int A = 1;
        const int AAAA = 28;

        public static void Resolve(string domain, ICollection<string> ipv4, ICollection<string> ipv6)
        {
            foreach (var server in Resolvers)
            {
                bool any = false;
                any |= QueryInto(domain, A, server, ipv4);
                any |= QueryInto(domain, AAAA, server, ipv6);
                if (any) return; // first resolver that answers is enough
            }
        }

        static bool QueryInto(string domain, int qtype, string server, ICollection<string> outList)
        {
            try
            {
                byte[] query = BuildQuery(domain, qtype);
                using (var udp = new UdpClient())
                {
                    udp.Client.ReceiveTimeout = 2000;
                    udp.Connect(server, 53);
                    udp.Send(query, query.Length);
                    IPEndPoint ep = null;
                    byte[] resp = udp.Receive(ref ep);
                    return ParseAnswers(resp, qtype, outList);
                }
            }
            catch
            {
                return false;
            }
        }

        static byte[] BuildQuery(string domain, int qtype)
        {
            var msg = new List<byte>();
            var rnd = new Random();
            msg.Add((byte)rnd.Next(256)); msg.Add((byte)rnd.Next(256)); // transaction id
            msg.Add(0x01); msg.Add(0x00); // flags: recursion desired
            msg.Add(0x00); msg.Add(0x01); // QDCOUNT = 1
            msg.Add(0x00); msg.Add(0x00); // ANCOUNT
            msg.Add(0x00); msg.Add(0x00); // NSCOUNT
            msg.Add(0x00); msg.Add(0x00); // ARCOUNT

            foreach (var label in domain.Split('.'))
            {
                if (label.Length == 0) continue;
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                msg.Add((byte)bytes.Length);
                msg.AddRange(bytes);
            }
            msg.Add(0x00); // end of QNAME
            msg.Add((byte)(qtype >> 8)); msg.Add((byte)(qtype & 0xFF)); // QTYPE
            msg.Add(0x00); msg.Add(0x01); // QCLASS = IN
            return msg.ToArray();
        }

        static bool ParseAnswers(byte[] buf, int qtype, ICollection<string> outList)
        {
            if (buf.Length < 12) return false;

            int qdcount = (buf[4] << 8) | buf[5];
            int ancount = (buf[6] << 8) | buf[7];
            int pos = 12;

            for (int i = 0; i < qdcount; i++)
            {
                SkipName(buf, ref pos);
                pos += 4; // QTYPE + QCLASS
            }

            bool found = false;
            for (int i = 0; i < ancount; i++)
            {
                SkipName(buf, ref pos);
                if (pos + 10 > buf.Length) break;

                int type = (buf[pos] << 8) | buf[pos + 1];
                pos += 8; // TYPE(2) + CLASS(2) + TTL(4)
                int rdlen = (buf[pos] << 8) | buf[pos + 1];
                pos += 2;
                if (pos + rdlen > buf.Length) break;

                if (type == qtype && ((type == A && rdlen == 4) || (type == AAAA && rdlen == 16)))
                {
                    var addr = new byte[rdlen];
                    Array.Copy(buf, pos, addr, 0, rdlen);
                    outList.Add(new IPAddress(addr).ToString());
                    found = true;
                }
                pos += rdlen;
            }
            return found;
        }

        // Advance past a domain name, honoring compression pointers (0xC0).
        static void SkipName(byte[] buf, ref int pos)
        {
            while (pos < buf.Length)
            {
                byte len = buf[pos];
                if (len == 0) { pos++; return; }
                if ((len & 0xC0) == 0xC0) { pos += 2; return; } // pointer terminates the name
                pos += 1 + len;
            }
        }
    }
}
