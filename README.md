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
```cmd
# Enable RDP shadowing
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow /T REG_DWORD /D 2 /F

# Run the tool
shadow-capture.exe C:\captures -t 5

# Disable RDP shadowing
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow
