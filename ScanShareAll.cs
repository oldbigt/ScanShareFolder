using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

class UltimateShareScanner
{
    // --- Windows API: 列舉分享清單 ---
    [DllImport("Netapi32.dll", SetLastError = true)]
    public static extern int NetShareEnum([MarshalAs(UnmanagedType.LPWStr)] string servername, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

    [DllImport("Netapi32.dll", SetLastError = true)]
    public static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1
    {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;
    }

    // --- Windows API: 網路連線掛載 ---
    [DllImport("mpr.dll")]
    private static extern int WNetAddConnection2(NetResource netResource, string password, string username, int flags);

    [DllImport("mpr.dll")]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    [StructLayout(LayoutKind.Sequential)]
    public class NetResource
    {
        public int Scope; public int Type; public int DisplayType; public int Usage;
        public string LocalName; public string RemoteName; public string Comment; public string Provider;
    }

    static void Main(string[] args)
    {
        string inputFile = "ip_list.txt";
        string outputFile = "ScanReport.csv";

        if (!File.Exists(inputFile)) {
            File.WriteAllText(inputFile, "127.0.0.1\n192.168.1.1");
            Console.WriteLine($"請在 {inputFile} 填入 IP 後執行。"); return;
        }

        Console.Write("使用者名稱 (Domain\\User): ");
        string user = Console.ReadLine();
        Console.Write("密碼: ");
        string pass = ReadPassword();
        Console.WriteLine("\n\n開始掃描...\n--------------------------------------");

        StringBuilder csv = new StringBuilder("IP,Path,ShareType,CanRead,CanWrite,Note\n");
        string[] ips = File.ReadAllLines(inputFile);

        foreach (string ip in ips)
        {
            string targetIp = ip.Trim();
            if (string.IsNullOrEmpty(targetIp)) continue;

            Console.WriteLine($"[*] IP: {targetIp}");
            if (!PingHost(targetIp)) {
                csv.AppendLine($"{targetIp},,,False,False,Offline");
                continue;
            }

            // 1. 取得公開分享清單
            List<string> foundShares = EnumNetShares(targetIp);
            
            // 2. 加入常見隱藏分享進行嘗試 (暴力破解)
            string[] hiddenGuesses = { "C$", "D$", "ADMIN$" };
            foreach (var h in hiddenGuesses) if (!foundShares.Contains(h)) foundShares.Add(h);

            foreach (string share in foundShares)
            {
                string fullPath = $@"\\{targetIp}\{share}";
                bool isHidden = share.EndsWith("$");

                // 3. 建立網路連線
                int ret = ConnectToShare(fullPath, user, pass);
                if (ret == 0 || ret == 1219)
                {
                    // 4. 測試讀寫
                    var (read, write) = TestFolderAccess(fullPath);
                    csv.AppendLine($"{targetIp},{fullPath},{(isHidden ? "Hidden" : "Public")},{read},{write},Success");
                    Console.WriteLine($"   > [{ (isHidden ? "隱藏" : "公開") }] {share} -> 讀:{read} 寫:{write}");

                    // 5. 掃描下一層目錄
                    try {
                        foreach (var subDir in Directory.GetDirectories(fullPath)) {
                            var (sRead, sWrite) = TestFolderAccess(subDir);
                            csv.AppendLine($"{targetIp},{subDir},SubDirectory,{sRead},{sWrite},OK");
                        }
                    } catch { /* 無法列子目錄 */ }

                    WNetCancelConnection2(fullPath, 0, true);
                }
                else {
                    if (!isHidden) // 公開分享但連不上才記錄
                        csv.AppendLine($"{targetIp},{fullPath},Public,False,False,Error Code {ret}");
                }
            }
        }

        File.WriteAllText(outputFile, csv.ToString(), Encoding.UTF8);
        Console.WriteLine($"\n[完成] 報告: {outputFile}");
    }

    static int ConnectToShare(string path, string user, string pass) {
        NetResource nr = new NetResource { Type = 1, RemoteName = path };
        return WNetAddConnection2(nr, pass, user, 0);
    }

    static (bool read, bool write) TestFolderAccess(string path) {
        bool r = false, w = false;
        try {
            Directory.GetDirectories(path); r = true;
            string testFile = Path.Combine(path, Guid.NewGuid().ToString() + ".tmp");
            File.Create(testFile).Dispose();
            File.Delete(testFile);
            w = true;
        } catch { }
        return (r, w);
    }

    static List<string> EnumNetShares(string server) {
        List<string> shares = new List<string>();
        IntPtr bufPtr; int read, total, handle = 0;
        if (NetShareEnum(server, 1, out bufPtr, -1, out read, out total, ref handle) == 0) {
            for (int i = 0; i < read; i++) {
                SHARE_INFO_1 si = (SHARE_INFO_1)Marshal.PtrToStructure(new IntPtr(bufPtr.ToInt64() + i * Marshal.SizeOf(typeof(SHARE_INFO_1))), typeof(SHARE_INFO_1));
                if ((si.shi1_type & 0x3) == 0) shares.Add(si.shi1_netname);
            }
            NetApiBufferFree(bufPtr);
        }
        return shares;
    }

    static bool PingHost(string ip) {
        try { using (Ping p = new Ping()) return p.Send(ip, 300).Status == IPStatus.Success; } catch { return false; }
    }

    static string ReadPassword() {
        string p = ""; ConsoleKeyInfo k;
        while ((k = Console.ReadKey(true)).Key != ConsoleKey.Enter) {
            if (k.Key == ConsoleKey.Backspace && p.Length > 0) { p = p.Remove(p.Length - 1); Console.Write("\b \b"); }
            else if (!char.IsControl(k.KeyChar)) { p += k.KeyChar; Console.Write("*"); }
        }
        return p;
    }
}
