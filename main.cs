using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

class ShareScanner
{
    // --- Windows API 用於掛載網路資源 ---
    [DllImport("mpr.dll")]
    private static extern int WNetAddConnection2(NetResource netResource, string password, string username, int flags);

    [DllImport("mpr.dll")]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    [StructLayout(LayoutKind.Sequential)]
    public class NetResource
    {
        public int Scope;
        public int Type;
        public int DisplayType;
        public int Usage;
        public string LocalName;
        public string RemoteName;
        public string Comment;
        public string Provider;
    }

    public class ScanResult
    {
        public string IP { get; set; }
        public string ShareName { get; set; }
        public bool CanRead { get; set; }
        public bool CanWrite { get; set; }
        public string Note { get; set; }
    }

    static void Main(string[] args)
    {
        // 1. 手動輸入憑據
        Console.Write("請輸入目標電腦使用者名稱 (如 Administrator): ");
        string username = Console.ReadLine();
        Console.Write("請輸入密碼: ");
        string password = ReadPassword(); // 隱藏密碼輸入
        Console.WriteLine("\n--------------------------------------");

        List<string> ipList = new List<string> { "192.168.1.10", "127.0.0.1" };
        List<ScanResult> results = new List<ScanResult>();

        foreach (var ip in ipList)
        {
            Console.WriteLine($"[*] 正在處理: {ip}");
            if (!PingHost(ip))
            {
                results.Add(new ScanResult { IP = ip, Note = "無法連線 (Ping Fail)" });
                continue;
            }

            try
            {
                // 2. 透過 WMI 獲取分享清單 (帶帳密)
                var shares = GetShares(ip, username, password);

                foreach (var share in shares)
                {
                    string networkPath = $@"\\{ip}\{share}";
                   
                    // 3. 檢查讀寫權限
                    var (canRead, canWrite) = CheckPermissions(networkPath, username, password);

                    results.Add(new ScanResult
                    {
                        IP = ip,
                        ShareName = share,
                        CanRead = canRead,
                        CanWrite = canWrite
                    });
                }
            }
            catch (Exception ex)
            {
                results.Add(new ScanResult { IP = ip, Note = $"錯誤: {ex.Message}" });
            }
        }

        ExportToCsv(results, "ScanResults.csv");
        Console.WriteLine("\n[完成] 結果已儲存至 ScanResults.csv");
    }

    static List<string> GetShares(string ip, string user, string pass)
    {
        List<string> shareNames = new List<string>();
        ConnectionOptions options = new ConnectionOptions
        {
            Username = user,
            Password = pass,
            Impersonation = ImpersonationLevel.Impersonate,
            EnablePrivileges = true
        };

        ManagementScope scope = new ManagementScope($@"\\{ip}\root\cimv2", options);
        scope.Connect();

        ObjectQuery query = new ObjectQuery("SELECT Name FROM Win32_Share");
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
        {
            foreach (ManagementObject m in searcher.Get())
            {
                shareNames.Add(m["Name"].ToString());
            }
        }
        return shareNames;
    }

    static (bool canRead, bool canWrite) CheckPermissions(string path, string user, string pass)
    {
        bool canRead = false;
        bool canWrite = false;

        NetResource nr = new NetResource { Type = 1, RemoteName = path };

        // 建立臨時連線以取得權限
        int ret = WNetAddConnection2(nr, pass, user, 0);

        if (ret == 0 || ret == 1219) // 0: 成功, 1219: 已有連線(重複使用)
        {
            try
            {
                Directory.GetDirectories(path);
                canRead = true;

                string testFile = Path.Combine(path, Guid.NewGuid().ToString() + ".tmp");
                File.Create(testFile).Dispose();
                File.Delete(testFile);
                canWrite = true;
            }
            catch { /* 權限不足 */ }
            finally
            {
                WNetCancelConnection2(path, 0, true);
            }
        }

        return (canRead, canWrite);
    }

    // 輔助函式：Ping 測試
    static bool PingHost(string ip)
    {
        try { using (Ping p = new Ping()) return p.Send(ip, 500).Status == IPStatus.Success; }
        catch { return false; }
    }

    // 輔助函式：輸出 CSV
    static void ExportToCsv(List<ScanResult> results, string fileName)
    {
        StringBuilder csv = new StringBuilder("IP,ShareName,CanRead,CanWrite,Note\n");
        foreach (var r in results)
            csv.AppendLine($"{r.IP},{r.ShareName},{r.CanRead},{r.CanWrite},{r.Note}");
        File.WriteAllText(fileName, csv.ToString(), Encoding.UTF8);
    }

    // 輔助函式：隱藏密碼輸入
    static string ReadPassword()
    {
        string pass = "";
        do {
            ConsoleKeyInfo key = Console.ReadKey(true);
            if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter) {
                pass += key.KeyChar; Console.Write("*");
            } else if (key.Key == ConsoleKey.Backspace && pass.Length > 0) {
                pass = pass.Substring(0, (pass.Length - 1)); Console.Write("\b \b");
            } else if (key.Key == ConsoleKey.Enter) break;
        } while (true);
        return pass;
    }
}
