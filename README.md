# Poison Ivy Remote Access Trojan Analysis & Threat Detection Logic

### Threat Profile Overview

Poison Ivy is a Remote Access Trojan (RAT) that was identified in 2005 and has been prevalent in cybercrime for years after. It has been used to target government organizations, chemical manufacturers, human rights groups, and defence contractors by a large variety of hacking groups and operations, including at least three separate advanced persistent threat (APT) campaigns. It was designed for the purpose of remotely monitoring victims while also exfiltrating user credentials and files. It is often spread through malicious Word or PDF attachments in spearphishing emails. In 2013, FireEye disseminated a detailed report on Poison Ivy and provided its typical attack sequence:

- The attacker sets up a custom Poison Ivy (PIVY) server, incorporating details on how the RAT will install itself on the target computer, enabled features, and the encryption password, among others.
- The attacker sends the PIVY server installation file to the target's computer. The target opens the infected email and executes the file, or visits a compromised website.
- The server installation file executes on the target computer and downloads additional code through an encrypted communication channel to avoid antivirus detection.
- Once the PIVY server is running on the target machine, the attacker uses a Windows GUI client to control the target computer

### Purpose

This project aims to do some static analysis of Poison Ivy through reverse engineering for learning purposes, so that based on our findings we can create our own detection rules. The sample used is from this [github repository](https://github.com/killeven/Poison-Ivy-Reload/tree/master)

## Reverse Engineering (Ghidra) 

<img width="1645" height="883" alt="image" src="https://github.com/user-attachments/assets/ed8898b0-ea4f-4e7b-b297-c6afbe34249f" />

Once the .exe file has been run through ghidra we are met with the analysed program files and the first thought I had when I did this project for fun before is to look for any system dlls. 

<img width="1055" height="631" alt="image" src="https://github.com/user-attachments/assets/687b9399-cf08-46ca-b575-a976c613d6ee" />

```
full discovered list:

0x1 WS2_32.dll socket
0x5 WS2_32.dll connect
0x9 WS2_32.dll closesocket
0xd WS2_32.dll send
0x11 WS2_32.dll recv
0x15 WS2_32.dll ntohs
0x19 WS2_32.dll inet_addr
0x1d WS2_32.dll gethostbyname
0x21 kernel32.dll VirtualAlloc
0x25 kernel32.dll VirtualFree
0x29 kernel32.dll CreateThread
0x2d kernel32.dll CreateProcessA
0x31 ADVAPI32.dll RegCloseKey
0x35 ADVAPI32.dll RegOpenKeyExA
0x39 ADVAPI32.dll RegQueryValueExA
0x3d ADVAPI32.dll RegSetValueExA
0x41 ADVAPI32.dll RegDeleteKeyA
0x45 ADVAPI32.dll RegCreateKeyExA
0x49 ADVAPI32.dll RegQueryInfoKeyA
0x4d ADVAPI32.dll RegEnumKeyExA
0x51 kernel32.dll DeleteFileA
0x55 kernel32.dll CopyFileA
0x59 kernel32.dll CreateFileA
0x5d USER32.dll GetKeyNameTextA
0x61 USER32.dll GetActiveWindow
0x65 USER32.dll GetWindowTextA
0x69 kernel32.dll WriteFile
0x6d USER32.dll CallNextHookEx
0x71 kernel32.dll SetFilePointer
0x75 USER32.dll ToAscii
0x79 USER32.dll GetKeyboardState
0x7d kernel32.dll GetLocalTime
0x81 kernel32.dll lstrcatA
0x85 kernel32.dll CreateMutexA
0x89 ntdll.dll RtlGetLastWin32Error
0x8d kernel32.dll GetFileTime
0x91 kernel32.dll SetFileTime
0x95 kernel32.dll OpenProcess
0x99 WS2_32.dll select
0x9d kernel32.dll LoadLibraryA
0xa1 kernel32.dll CloseHandle
0xa5 kernel32.dll Sleep
0xa9 ntdll.dll RtlMoveMemory
0xad ntdll.dll RtlZeroMemory
0xb1 kernel32.dll VirtualAllocEx
0xb5 kernel32.dll WriteProcessMemory
0xb9 kernel32.dll CreateToolhelp32Snapshot
0xbd kernel32.dll Process32First
0xc1 kernel32.dll Process32Next
0xc9 kernel32.dll CreateRemoteThread
0xcd kernel32.dll lstrcmpiA
```

and after navigating through the analysed functions that ghidra has pulled for us, we can see `kernel32.dll`. This a huge find because poison ivy actually doesn't have an import address table (IAT), where it would usually import functions from, instead the malware uses APIs for launching external processes (CreateProcessA), and modifying and querying the registry (for persistence with the Run key). The sequence of `VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread` is used to execute code inside legitimate windows processes in order to bypass basic defensive tooling **(MITRE ATT&CK TECHNIQUE: T1055.012)**. It's keylogger functionality is defined by the `SetWindowsHookEx, CallNextHookEx, GetKeyboardState, and ToAscii` sequence **(MITRE ATT&CK TECHNIQUE: T1056.001)**. Finally the `SetFileTime` API is for anti-forensic analysis by forging timestamp metadata **(MITRE ATT&CK TECHNIQUE: T1070.006)**

Due to the sample being a proof of concept unfortunately there really isn't much more depth to the malware to dive into. That unfortunately means a YARA ruling will be of low operational value but we can still define a sigma rule for it. 

## Sigma Rule 1 : Process Injection

```YAML
title: Suspicious Process Spawning Injected Host Binary
status: ProofOfConcept
description: Detects unusual parent processes spawning explorer.exe or svchost.exe, which indicates process injection or hollowing.
author: zaw44d
tags:
    - attack.defense_evasion
    - attack.t1055.012
logsource:
    category: process_creation
    system: windows
detection:
    selection:
        Image|endswith:
            - '\explorer.exe'  # The target process being spawned
            - '\svchost.exe'
    filter_legit:
        ParentImage|endswith:
            - '\userinit.exe'  # Whitelists ONLY legitimate Windows system parents
            - '\services.exe'
            - '\wininit.exe'
    condition: selection and not filter_legit
falsepositives:
    - Admin scripts or software deployment tools
```

The rule targets the malware's behaviour of injecting it's shellcode into a processes memory space like `explorer.exe` or `svchost.exe`. If a random executable were to spawn one of these two it would instantly flag it and stop it before the injection is successful. 

## Sigma Rule 2 : Remote Threat Injection

```YAML
title: Suspicious Process Spawning Injected Host Binary
status: ProofOfConcept
description: Detects a process injecting code into explorer.exe or svchost.exe using remote threads.
author: zaw44d
tags:
    - attack.defense_evasion
    - attack.t1055.001
logsource:
    category: create_remote_thread
    system: windows
detection:
    selection:
        TargetImage|endswith:
            - '\explorer.exe'  # Process receiving the injected thread
            - '\svchost.exe'
    filter_same_process:
        SourceImage: '$TargetImage'  # Ignores a process creating threads inside ITSELF (normal behavior)
    filter_system:
        SourceImage|endswith:
            - '\services.exe'  # Filters out valid OS/service activity
            - '\csrss.exe'
    condition: selection and not filter_same_process and not filter_system
falsepositives:
    - Antivirus or EDR agents injecting hooks
```
Rule 1 catches the process creation, while Rule 2 catches the actual code execution transition. The API function `CreateRemoteThread` is the final line in the sequence of events, and is responsible for making the remote process run the shellcode. Thus allowing the ruling to detect this behaviour to terminate the process. 

Thank you for taking time to go through this, it was a lot of fun. The detection rules will be uploaded to the repository. 
