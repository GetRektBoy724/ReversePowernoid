@echo off
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /out:server.exe server.cs

C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll /target:winexe /out:client.exe client.cs