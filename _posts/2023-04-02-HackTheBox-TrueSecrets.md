---
title: HackTheBox - TrueSecrets
author: solidgoat
date: 2023-04-02 18:00:00 EDT
categories: [HackTheBox, Forensics]
tags: [forensics, challenges, hackthebox, htb, walkthrough, easy, memory dump, volatility, truecrypt, decoding, cyberchef]
image:
  path: /assets/img/posts/TrueSecrets/forensics-logo.png
  width: 200
  height: 200
  alt: Walkthrough of TrueSecrets from HackTheBox
---

## Task

Our cybercrime unit has been investigating a well-known APT group for several months. The group has been responsible for several high-profile attacks on corporate organizations. However, what is interesting about that case, is that they have developed a custom command & control server of their own. Fortunately, our unit was able to raid the home of the leader of the APT group and take a memory capture of his computer while it was still powered on. Analyze the capture to try to find the source code of the server.

### Tools Used

* [Volatility3](https://github.com/volatilityfoundation/volatility3)
* [VeraCrypt](https://www.veracrypt.fr/en/Home.html)
* Docker
* [CyberChef](https://gchq.github.io/CyberChef/)

## Initial Assessment

All we're given is a zip file that contains the memory dump of the attacker's computer.

I'm going to be using [Volatility3](https://github.com/volatilityfoundation/volatility3) to analyze the memory dump.

Guessing that it was a Windows system, I used the `windows.info.Info` plugin to get some initial information.

The OS is Windows 7 SP1 - Build 7601.

<img src="/assets/img/posts/TrueSecrets/volatility-windows-info.png">

The next thing I did was list the processes that were running at the time using `windows.pstree.PsTree` plugin.

There are two that stood out - `TrueCrypt.exe` and `7zFM.exe`.

<img src="/assets/img/posts/TrueSecrets/volatility-process-tree.png">

I wanted to see what commands each process was running at the time of the dump, so I used the `windows.cmdline.CmdLine` plugin.

We can see that the `7zFM.exe` process had a zip file opened - `backup_development.zip`. But there was nothing for the `TrueCrypt.exe` process.

<img src="/assets/img/posts/TrueSecrets/volatility-cmdline.png">

So we'll list the handles for `7zFM.exe` and filter on ".zip".

<img src="/assets/img/posts/TrueSecrets/volatility-backup_development-zip-handle.png">

Now that we have the memory address (`0x843f6158`), we should be able to grab the file out of the memory dump.

<img src="/assets/img/posts/TrueSecrets/volatility-backup_development-zip.png">

And that contains the TrueCrypt database file - `development.tc`.

<img src="/assets/img/posts/TrueSecrets/truecrypt-file.png" width="75%" height="75%">

## Breaking Into the TrueCrypt Database

I initially I tried to crack the database using `hashcat` and the `rockyou.txt` wordlist, but that didn't work.

<img src="/assets/img/posts/TrueSecrets/truecrypt-hashcat-exhausted.png" width="75%" height="75%">

I tried searching through the memory dump for other files that might contain the password, but couldn't find anything. And the registry hives didn't contain `HKEY_CURRENT_USER`, so I didn't have access to recent commands.

<img src="/assets/img/posts/TrueSecrets/volatility-registry-hives.png">

I wasn't sure how else to get this information, but every time I Googled for a way to get a TrueCrypt database's password or masterkey with [Volatility3](https://github.com/volatilityfoundation/volatility3), it would show a plugin available in [Volatility2](https://github.com/volatilityfoundation/volatility) - `truecryptsummary`.

[Volatility3](https://github.com/volatilityfoundation/volatility3) was rewritten to support Python3, while [Volatility2](https://github.com/volatilityfoundation/volatility) is no longer being developed and written in Python2. But some of the plugins, `truecryptsummary` being one of them, weren't ported over to [Volatility3](https://github.com/volatilityfoundation/volatility3).

I tried just copying that file (`tcaudit.py`) to the plugins directory in [Volatility3](https://github.com/volatilityfoundation/volatility3), but that obviously failed, and I wasn't about to rewrite that for Python3 using the Volatility framework.

I then tried to get [Volatility2](https://github.com/volatilityfoundation/volatility) to run on my Kali VM, but of course the one plugin that I needed wouldn't load because it was missing a library - `Crypto.Hash`. And getting `pycryptodome` (successor of `pycrypto`) using `pip` would only install it for Python3, not for Python2.

<img src="/assets/img/posts/TrueSecrets/volatility2-fail-to-load.png">

I had an idea. I went to [Docker Hub](https://hub.docker.com/) to see if there was a version of Python2.7 that I could use.

And look at that. There is.

<img src="/assets/img/posts/TrueSecrets/dockerhub-python2.png">

I downloaded the image and ran an interactive container and mounted the directory that contained the memory dump.

<img src="/assets/img/posts/TrueSecrets/docker-python2-interactive.png">

I cloned [Volatility2](https://github.com/volatilityfoundation/volatility) and downloaded the necessary libraries.

And was able to successfully run [Volatility2](https://github.com/volatilityfoundation/volatility) AND obtain the TrueCrypt database password.

<img src="/assets/img/posts/TrueSecrets/truecrypt-password.png">

## Decoding the Commands and Output

I mounted the TrueCrypt database using [VeraCrypt](https://www.veracrypt.fr/en/Home.html) (successor to TrueCrypt).

<img src="/assets/img/posts/TrueSecrets/veracrypt-mount.png" width="75%" height="75%">

And was able to view the files within.

<img src="/assets/img/posts/TrueSecrets/truecrypt-database-files.png" width="75%" height="75%">

Of course the session files are not just `base64`, but encoded using `DES`.

<img src="/assets/img/posts/TrueSecrets/encoded-files.png" width="75%" height="75%">

It appears the `AgentServer.cs` starts the server and runs a custom `Encrypt()` method to encode the input and output.

<img src="/assets/img/posts/TrueSecrets/agentserver-csharp-file.png">

Being the lazy person that I am, I didn't feel like reversing this in `C#` so I looked to see if [CyberChef](https://gchq.github.io/CyberChef/) had a recipe for decoding DES. And it does!

I used the `From Base64` recipe before the `DES Decrypt` one. And since I had the key and IV, I just threw that in, and was able to see the decoded input and output.

<img src="/assets/img/posts/TrueSecrets/cyber-chef-decode1.png">

...and get the flag.

<img src="/assets/img/posts/TrueSecrets/flag.png">
