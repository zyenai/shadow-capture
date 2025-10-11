# shadow-capture
Enumerate, shadow, and screenshot RDP sessions on a local server

## Features
- Multi-threaded concurrent session capture
- Automatic session filtering (skips own session and disconnected sessions)

## Prerequisites
- Windows Server 2019+ or Windows 10+
- Administrator privileges
- RDP shadowing enabled

## Usage
Enable RDP shadowing
```cmd
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow /T REG_DWORD /D 2 /F
```

Run shadow-capture
```cmd
shadow-capture.exe [output_dir] [-t threads]

ARGUMENTS:
  output_dir          Directory to save screenshots (default: current directory)
  -t, --threads N     Number of concurrent captures (1-10, default: 3)
  -h, --help          Show this help message
```

Disable RDP shadowing
```cmd
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow
```
