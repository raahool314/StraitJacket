using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace StraitJacket
{
    // Decides whether enforcement should be suspended, based on who is logged on.
    //
    // Windows resolves names through one shared service and reads one shared
    // hosts file, so the DNS layers cannot be scoped to a user -- whatever they
    // block, they block for everyone. Rather than restrain administrators too,
    // the service watches sessions and stands down while the only people at the
    // machine are administrators.
    //
    // The rule is deliberately conservative:
    //
    //   suspend  <=>  at least one user is logged on
    //                 AND every logged-on user is an administrator
    //
    // A standard user's session counts whether it is active, switched away from,
    // or locked -- fast user switching leaves sessions alive, and "stop when an
    // admin logs in" would otherwise hand a standard user an unrestricted
    // machine to switch straight back into. No sessions at all (boot, the logon
    // screen) enforces, and so does any failure to read the session list.
    static class SessionGuard
    {
        const string SidAdministrators = "S-1-5-32-544";

        // Evaluates the current sessions. Returns false if the session list
        // could not be read, in which case the caller must keep enforcing.
        public static bool TryEvaluate(out bool suspend, out string summary)
        {
            suspend = false;
            summary = null;

            List<string> admins = new List<string>();
            List<string> standard = new List<string>();
            if (!Enumerate(admins, standard)) return false;

            int total = admins.Count + standard.Count;
            suspend = total > 0 && standard.Count == 0;

            if (total == 0) summary = "no users logged on";
            else summary = Describe("administrator", admins) +
                           (standard.Count > 0 ? ", " + Describe("standard user", standard) : "");
            return true;
        }

        static string Describe(string noun, List<string> names)
        {
            string label = names.Count == 1 ? noun : noun + "s";
            return names.Count + " " + label +
                   (names.Count > 0 ? " (" + string.Join(", ", names.ToArray()) + ")" : "");
        }

        static bool Enumerate(List<string> admins, List<string> standard)
        {
            IntPtr buffer = IntPtr.Zero;
            int count = 0;
            try
            {
                if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buffer, out count)) return false;

                int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                for (int i = 0; i < count; i++)
                {
                    var info = (WTS_SESSION_INFO)Marshal.PtrToStructure(
                        new IntPtr(buffer.ToInt64() + (long)i * size), typeof(WTS_SESSION_INFO));

                    if (info.SessionId == 0) continue; // session 0 hosts services, not people

                    IntPtr token = IntPtr.Zero;
                    // The authoritative test for "somebody is logged on here":
                    // this fails for the logon screen and for empty sessions.
                    if (!WTSQueryUserToken(info.SessionId, out token)) continue;
                    try
                    {
                        string name = UserName(info.SessionId, info.SessionId.ToString());
                        if (IsAdminToken(token)) admins.Add(name); else standard.Add(name);
                    }
                    finally { CloseHandle(token); }
                }
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
            }
        }

        static string UserName(int sessionId, string fallback)
        {
            IntPtr buf = IntPtr.Zero;
            int bytes;
            try
            {
                if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTSUserName, out buf, out bytes) ||
                    buf == IntPtr.Zero)
                    return fallback;
                string name = Marshal.PtrToStringAnsi(buf);
                return string.IsNullOrEmpty(name) ? fallback : name;
            }
            catch { return fallback; }
            finally { if (buf != IntPtr.Zero) WTSFreeMemory(buf); }
        }

        // Membership is read from the token's groups rather than from the
        // account, so nested groups count. Group attributes are ignored on
        // purpose: an unelevated administrator carries Administrators as a
        // deny-only SID, and that still means the person is an administrator.
        static bool IsAdminToken(IntPtr token)
        {
            IntPtr buf = IntPtr.Zero;
            try
            {
                int len = 0;
                GetTokenInformation(token, TokenGroups, IntPtr.Zero, 0, out len);
                if (len <= 0) return false;

                buf = Marshal.AllocHGlobal(len);
                if (!GetTokenInformation(token, TokenGroups, buf, len, out len)) return false;

                // TOKEN_GROUPS { DWORD GroupCount; SID_AND_ATTRIBUTES Groups[]; }
                // SID_AND_ATTRIBUTES is a pointer plus a DWORD, padded to the
                // pointer alignment (8 bytes on x86, 16 on x64).
                int groups = Marshal.ReadInt32(buf);
                int entry = IntPtr.Size * 2;
                for (int i = 0; i < groups; i++)
                {
                    IntPtr row = new IntPtr(buf.ToInt64() + IntPtr.Size + (long)i * entry);
                    if (SidToString(Marshal.ReadIntPtr(row)) == SidAdministrators) return true;
                }
                return false;
            }
            catch { return false; }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        }

        static string SidToString(IntPtr sid)
        {
            if (sid == IntPtr.Zero) return null;
            IntPtr str = IntPtr.Zero;
            try
            {
                if (!ConvertSidToStringSid(sid, out str)) return null;
                return Marshal.PtrToStringUni(str);
            }
            finally { if (str != IntPtr.Zero) LocalFree(str); }
        }

        // ---- interop -----------------------------------------------------------

        const int TokenGroups = 2;
        const int WTSUserName = 5;

        [StructLayout(LayoutKind.Sequential)]
        struct WTS_SESSION_INFO
        {
            public int SessionId;
            public IntPtr pWinStationName;
            public int State;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version,
                                                out IntPtr sessionInfo, out int count);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQueryUserToken(int sessionId, out IntPtr token);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass,
                                                      out IntPtr buffer, out int bytesReturned);

        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr p);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buf, int len, out int needed);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);
    }
}
