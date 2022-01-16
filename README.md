# ReversePowernoid
ReversePowernoid is a reverse TCP C#-based Powershell, and it's really paranoid about Powershell's security and defense system. ReversePowernoid will disable CLM (Constrained Language Mode), ETW (Event Tracing for Windows), SBL (Script-Block Logging), and AMSI (Anti-Malware Scan Interface) at startup, if it fails to disable one of them, it automatically aborts the process and quits and obviously, it will not connect to the server/attacker. The TCP traffic will be encrypted with AES with a hardcoded key (I know its a pretty bad idea, but its good enough for now).
### Inspired by mgeeky's Stracciatella
### Source Code will be uploaded ASAP!
