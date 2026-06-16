using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace StraitJacket
{
    // A minimal local DNS server bound to 127.0.0.1:53 (and ::1) over UDP+TCP.
    // For blocked names it answers from an in-memory set (O(1)) with 0.0.0.0/::;
    // SafeSearch hosts get their pinned IP; everything else is forwarded to an
    // upstream resolver and relayed back. This replaces a giant hosts file for
    // large lists, removing the Windows DNS Client's large-file latency.
    //
    // Matching is EXACT (not suffix-based) to preserve precise behavior: e.g.
    // blocking duckduckgo.com must not block lite.duckduckgo.com, and blocking
    // google.com must not block mail.google.com.
    class DnsSinkhole
    {
        const int A = 1;
        const int AAAA = 28;

        readonly Action<string> _log;
        readonly string[] _upstreams = { "1.1.1.1", "8.8.8.8" };

        HashSet<string> _blocked = new HashSet<string>(StringComparer.Ordinal);
        Dictionary<string, string> _safeSearch = new Dictionary<string, string>(StringComparer.Ordinal);

        UdpClient _udp4, _udp6;
        TcpListener _tcp4, _tcp6;
        volatile bool _running;

        public DnsSinkhole(Action<string> log) { _log = log; }

        // Swap the in-memory data sets (called whenever the block list changes).
        public void Update(HashSet<string> blocked, Dictionary<string, string> safeSearch)
        {
            _blocked = blocked ?? new HashSet<string>(StringComparer.Ordinal);
            _safeSearch = safeSearch ?? new Dictionary<string, string>(StringComparer.Ordinal);
        }

        // Binds the listeners. Returns false if the primary UDP socket cannot
        // bind (in which case the caller must NOT pin system DNS to us).
        public bool Start()
        {
            _running = true;
            try
            {
                _udp4 = new UdpClient(new IPEndPoint(IPAddress.Loopback, 53));
            }
            catch (Exception ex)
            {
                _log("Sinkhole: failed to bind UDP 127.0.0.1:53 -> " + ex.Message);
                _running = false;
                return false;
            }
            StartThread(delegate { UdpLoop(_udp4); });

            bool v6 = false;
            try { _udp6 = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 53)); StartThread(delegate { UdpLoop(_udp6); }); v6 = true; }
            catch (Exception ex) { _log("Sinkhole: IPv6 UDP bind skipped -> " + ex.Message); }

            try { _tcp4 = new TcpListener(IPAddress.Loopback, 53); _tcp4.Start(); StartThread(delegate { TcpLoop(_tcp4); }); }
            catch (Exception ex) { _log("Sinkhole: TCP bind skipped -> " + ex.Message); }

            try { _tcp6 = new TcpListener(IPAddress.IPv6Loopback, 53); _tcp6.Start(); StartThread(delegate { TcpLoop(_tcp6); }); }
            catch (Exception ex) { _log("Sinkhole: IPv6 TCP bind skipped -> " + ex.Message); }

            _log(v6
                ? "Sinkhole: listening on 127.0.0.1:53 and [::1]:53 (UDP/TCP)."
                : "Sinkhole: listening on 127.0.0.1:53 (UDP/TCP); IPv6 unavailable.");
            return true;
        }

        public void Stop()
        {
            _running = false;
            try { if (_udp4 != null) _udp4.Close(); } catch { }
            try { if (_udp6 != null) _udp6.Close(); } catch { }
            try { if (_tcp4 != null) _tcp4.Stop(); } catch { }
            try { if (_tcp6 != null) _tcp6.Stop(); } catch { }
        }

        static void StartThread(ThreadStart body)
        {
            var t = new Thread(body) { IsBackground = true };
            t.Start();
        }

        // ---- UDP ---------------------------------------------------------------

        void UdpLoop(UdpClient server)
        {
            // The receive endpoint's family must match the socket's, otherwise
            // Receive() throws on the IPv6 socket and the loop spins silently
            // (binding ::1 but never answering).
            IPAddress anyAddr = server.Client.AddressFamily == AddressFamily.InterNetworkV6
                ? IPAddress.IPv6Any : IPAddress.Any;
            while (_running)
            {
                IPEndPoint remote = new IPEndPoint(anyAddr, 0);
                byte[] data;
                try { data = server.Receive(ref remote); }
                catch { if (!_running) break; continue; }

                byte[] d = data;
                IPEndPoint r = remote;
                ThreadPool.QueueUserWorkItem(delegate
                {
                    try
                    {
                        byte[] resp = BuildLocalResponse(d);
                        if (resp == null) resp = Forward(d, false);
                        if (resp != null) server.Send(resp, resp.Length, r);
                    }
                    catch { }
                });
            }
        }

        // ---- TCP ---------------------------------------------------------------

        void TcpLoop(TcpListener listener)
        {
            while (_running)
            {
                TcpClient client;
                try { client = listener.AcceptTcpClient(); }
                catch { if (!_running) break; continue; }
                ThreadPool.QueueUserWorkItem(delegate { HandleTcp(client); });
            }
        }

        void HandleTcp(TcpClient client)
        {
            try
            {
                using (client)
                using (NetworkStream ns = client.GetStream())
                {
                    ns.ReadTimeout = 4000;
                    byte[] lenBuf = ReadExactly(ns, 2);
                    if (lenBuf == null) return;
                    int len = (lenBuf[0] << 8) | lenBuf[1];
                    byte[] query = ReadExactly(ns, len);
                    if (query == null) return;

                    byte[] resp = BuildLocalResponse(query);
                    if (resp == null) resp = Forward(query, true);
                    if (resp == null) return;

                    byte[] outBuf = new byte[resp.Length + 2];
                    outBuf[0] = (byte)(resp.Length >> 8);
                    outBuf[1] = (byte)(resp.Length & 0xFF);
                    Array.Copy(resp, 0, outBuf, 2, resp.Length);
                    ns.Write(outBuf, 0, outBuf.Length);
                }
            }
            catch { }
        }

        static byte[] ReadExactly(Stream s, int n)
        {
            byte[] buf = new byte[n];
            int off = 0;
            while (off < n)
            {
                int r = s.Read(buf, off, n - off);
                if (r <= 0) return null;
                off += r;
            }
            return buf;
        }

        // ---- decision ----------------------------------------------------------

        // Returns a response if we answer locally (block/redirect), or null to
        // signal the caller to forward the query upstream.
        byte[] BuildLocalResponse(byte[] q)
        {
            string name;
            int qtype, qend;
            if (!TryParseQuestion(q, out name, out qtype, out qend)) return null;
            name = name.ToLowerInvariant();

            HashSet<string> blocked = _blocked;
            Dictionary<string, string> ss = _safeSearch;

            if (blocked.Contains(name))
                return BuildAnswer(q, qtype, qend, null);   // sink to 0.0.0.0 / ::

            string ip;
            if (ss.TryGetValue(name, out ip))
                return BuildAnswer(q, qtype, qend, ip);      // SafeSearch redirect

            return null; // forward
        }

        static bool TryParseQuestion(byte[] q, out string name, out int qtype, out int qend)
        {
            name = null; qtype = 0; qend = 0;
            if (q.Length < 12) return false;
            if (((q[2] & 0x80) != 0)) return false; // ignore responses
            int qd = (q[4] << 8) | q[5];
            if (qd < 1) return false;

            int pos = 12;
            var sb = new StringBuilder();
            while (true)
            {
                if (pos >= q.Length) return false;
                int len = q[pos++];
                if (len == 0) break;
                if ((len & 0xC0) == 0xC0) { pos++; break; } // compression (not expected here)
                if (pos + len > q.Length) return false;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(q, pos, len));
                pos += len;
            }
            if (pos + 4 > q.Length) return false;
            qtype = (q[pos] << 8) | q[pos + 1];
            pos += 4; // QTYPE + QCLASS
            qend = pos;
            name = sb.ToString();
            return true;
        }

        // Builds a NOERROR response. If redirectIp is null the name is sinked
        // (0.0.0.0 for A, :: for AAAA, NODATA for other types). If redirectIp is
        // a v4 address, A queries get it (AAAA -> NODATA so clients use A).
        static byte[] BuildAnswer(byte[] q, int qtype, int qend, string redirectIp)
        {
            byte[] rdata = null;
            if (qtype == A)
            {
                if (redirectIp == null) rdata = new byte[4]; // 0.0.0.0
                else
                {
                    IPAddress a;
                    if (IPAddress.TryParse(redirectIp, out a) &&
                        a.AddressFamily == AddressFamily.InterNetwork)
                        rdata = a.GetAddressBytes();
                }
            }
            else if (qtype == AAAA && redirectIp == null)
            {
                rdata = new byte[16]; // ::
            }

            int ancount = (rdata != null) ? 1 : 0;
            int answerLen = (rdata != null) ? (2 + 2 + 2 + 4 + 2 + rdata.Length) : 0;
            byte[] resp = new byte[qend + answerLen];
            Array.Copy(q, 0, resp, 0, qend); // header + question (drops any EDNS)

            byte rd = (byte)(q[2] & 0x01);
            resp[2] = (byte)(0x80 | rd); // QR=1, RD copied
            resp[3] = 0x80;              // RA=1, RCODE=0 (NOERROR)
            resp[6] = (byte)(ancount >> 8); resp[7] = (byte)(ancount & 0xFF);
            resp[8] = 0; resp[9] = 0;    // NSCOUNT
            resp[10] = 0; resp[11] = 0;  // ARCOUNT

            if (rdata != null)
            {
                int p = qend;
                resp[p++] = 0xC0; resp[p++] = 0x0C;                 // name -> pointer to question
                resp[p++] = (byte)(qtype >> 8); resp[p++] = (byte)(qtype & 0xFF);
                resp[p++] = 0x00; resp[p++] = 0x01;                 // CLASS IN
                resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 0x00; resp[p++] = 0x3C; // TTL 60
                resp[p++] = (byte)(rdata.Length >> 8); resp[p++] = (byte)(rdata.Length & 0xFF);
                Array.Copy(rdata, 0, resp, p, rdata.Length);
            }
            return resp;
        }

        // ---- forwarding --------------------------------------------------------

        byte[] Forward(byte[] query, bool tcp)
        {
            foreach (var up in _upstreams)
            {
                try
                {
                    if (tcp)
                    {
                        byte[] r = ForwardTcp(query, up);
                        if (r != null) return r;
                    }
                    else
                    {
                        using (var udp = new UdpClient())
                        {
                            udp.Client.ReceiveTimeout = 3000;
                            udp.Connect(up, 53);
                            udp.Send(query, query.Length);
                            IPEndPoint ep = null;
                            return udp.Receive(ref ep);
                        }
                    }
                }
                catch { }
            }
            return null; // all upstreams failed; client will time out and retry
        }

        byte[] ForwardTcp(byte[] query, string up)
        {
            using (var c = new TcpClient())
            {
                IAsyncResult ar = c.BeginConnect(up, 53, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(3000)) return null;
                c.EndConnect(ar);
                using (NetworkStream ns = c.GetStream())
                {
                    ns.ReadTimeout = 3000;
                    byte[] outBuf = new byte[query.Length + 2];
                    outBuf[0] = (byte)(query.Length >> 8);
                    outBuf[1] = (byte)(query.Length & 0xFF);
                    Array.Copy(query, 0, outBuf, 2, query.Length);
                    ns.Write(outBuf, 0, outBuf.Length);

                    byte[] lenBuf = ReadExactly(ns, 2);
                    if (lenBuf == null) return null;
                    int len = (lenBuf[0] << 8) | lenBuf[1];
                    return ReadExactly(ns, len);
                }
            }
        }
    }
}
