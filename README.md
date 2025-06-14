# TryHackMe
** This repo aims to help TryHackMe members to choose the right rooms. It is also proviving tags for each room to know what it is about and what tools are typically used in each room. **

:crossed_flags:	Path Learnings contain Modules. Modules contain Rooms. Many Rooms including Challenges are not in any module.:crossed_flags:	  
Go to [Path Learnings](#Path-Learnings)  
Go to [Modules](#Modules)  
Go to [Other rooms per categories](#Other-Rooms-per-Categories)  

## Path Learnings


### Computer Science Basics
    [Introduction to Cyber Security](#Introduction-to-Cyber-Security)  
    [Network Fundamentals](#Network-Fundamentals)  
    [How The Web Works](#How-The-Web-Works)  
    [Linux Fundamentals](#Linux-Fundamentals)  
    [Windows Fundamentals](#Windows-Fundamentals)

### Penetration Tester 
### Jr Penetration Tester
    [Introduction to Cyber Security](#Introduction-to-Cyber-Security)  
    [Introduction to Pentesting](#Introduction-to-Pentesting)  
    [Introduction to Web Hacking](#Introduction-to-Web-Hacking) 
    [Burp Suite](#Burp-Suite) 
    [Network Security](#Network-Security) 
    [Vulnerability Research](#Vulnerability-Research) 
    [Metasploit](#Metasploit) 
    [Privilege Escalation](#Privilege-Escalation) 
    [Jr. Penetration Tester Certification (PT1)](https://tryhackme.com/certification/junior-penetration-tester)

## Modules

### Compromising Active Directory
Learn and exploit Active Directory networks through core security issues stemming from misconfigurations.  
+ [Active Directory Basics](https://tryhackme.com/room/winadbasics) : This room will introduce the basic concepts and functionality provided by Active Directory.
+ [Breaching Active Directory](https://tryhackme.com/room/breachingad) : This network covers techniques and tools that can be used to acquire that first set of AD credentials that can then be used to enumerate AD.
+ [Enumerating Active Directory](https://tryhackme.com/room/adenumeration) : This room covers various Active Directory enumeration techniques, their use cases as well as drawbacks.
+ Lateral Movement and Pivoting : Learn about common techniques used to move laterally across a Windows network.
+ Exploiting Active Directory : Learn common AD exploitation techniques that can allow you to reach your goal in an AD environment.
+ Persisting Active Directory : Learn about common Active Directory persistence techniques that can be used post-compromise to ensure the blue team will not be able to kick you out during a red team exercise.
+ Credentials Harvesting : Apply current authentication models employed in modern environments to a red team approach.

### Introduction to Pentesting
+ [Pentesting Fundamentals](https://tryhackme.com/room/pentestingfundamentals) : Learn the important ethics and methodologies behind every pentest.
+ [Principles of Security](https://tryhackme.com/room/principlesofsecurity) : Learn the principles of information security that secures data and protects systems from abuse.

### Introduction to Web Hacking
+ [Walking An Application](https://tryhackme.com/room/walkinganapplication) : Manually review a web application for security issues using only your browsers developer tools. Hacking with just your browser, no tools or scripts.
+ [Content Discovery](https://tryhackme.com/room/contentdiscovery) : Learn the various ways of discovering hidden or private content on a webserver that could lead to new vulnerabilities.
+ [Subdomain Enumeration](https://tryhackme.com/room/subdomainenumeration) : Learn the various ways of discovering subdomains to expand your attack surface of a target.
+ [Authentication Bypass](https://tryhackme.com/room/authenticationbypass) : Learn how to defeat logins and other authentication mechanisms to allow you access to unpermitted areas.
+ [IDOR](https://tryhackme.com/room/idor) : Learn how to find and exploit IDOR vulnerabilities in a web application giving you access to data that you shouldn't have.
+ [File Inclusion](https://tryhackme.com/room/fileinc) : This room introduces file inclusion vulnerabilities, including Local File Inclusion (LFI), Remote File Inclusion (RFI), and directory traversal.
+ [Intro to SSRF](https://tryhackme.com/room/ssrfqi) : Learn how to exploit Server-Side Request Forgery (SSRF) vulnerabilities, allowing you to access internal server resources.
+ [Intro to Cross-site Scripting](https://tryhackme.com/room/xss) : Learn how to detect and exploit XSS vulnerabilities, giving you control of other visitor's browsers.
+ [Race Conditions](https://tryhackme.com/room/raceconditionsattacks) : Learn about race conditions and how they affect web application security.
+ [Command Injection](https://tryhackme.com/room/oscommandinjection) : Learn about a vulnerability allowing you to execute commands through a vulnerable app, and its remediations.
+ [SQL Injection](https://tryhackme.com/room/sqlinjectionlm) : Learn how to detect and exploit SQL Injection vulnerabilities.

### Burp Suite
+ [Burp Suite: The Basics](https://tryhackme.com/room/burpsuitebasics) : An introduction to using Burp Suite for web application pentesting.
+ [Burp Suite: Repeater](https://tryhackme.com/room/burpsuiterepeater) : Learn how to use Repeater to duplicate requests in Burp Suite.
+ [Burp Suite: Intruder](https://tryhackme.com/room/burpsuiteintruder) : Learn how to use Intruder to automate requests in Burp Suite.
+ [Burp Suite: Other Modules](https://tryhackme.com/room/burpsuiteom) : Take a dive into some of Burp Suite's lesser-known modules.
+ [Burp Suite: Extensions](https://tryhackme.com/room/burpsuiteextensions) : Learn how to use Extensions to broaden the functionality of Burp Suite.

### Network Security
+ [Passive Reconnaissance](https://tryhackme.com/room/passiverecon) : Learn about the essential tools for passive reconnaissance, such as whois, nslookup, and dig.
+ [Active Reconnaissance](https://tryhackme.com/room/activerecon) : Learn how to use simple tools such as traceroute, ping, telnet, and a web browser to gather information.
+ [Nmap Live Host Discovery](https://tryhackme.com/room/nmap01) : Learn how to use Nmap to discover live hosts using ARP scan, ICMP scan, and TCP/UDP ping scan.
+ [Nmap Basic Port Scans](https://tryhackme.com/room/nmap02) : Learn in-depth how nmap TCP connect scan, TCP SYN port scan, and UDP port scan work.
+ [Nmap Advanced Port Scans](https://tryhackme.com/room/nmap03) : Learn advanced techniques such as null, FIN, Xmas, and idle (zombie) scans, spoofing, in addition to FW and IDS evasion.
+ [Nmap Post Port Scans](https://tryhackme.com/room/nmap04) : Learn how to leverage Nmap for service and OS detection, use Nmap Scripting Engine (NSE), and save the results.
+ [Protocols and Servers](https://tryhackme.com/room/protocolsandservers) : Learn about common protocols such as HTTP, FTP, POP3, SMTP and IMAP, along with related insecurities.
+ [Protocols and Servers 2](https://tryhackme.com/room/protocolsandservers2) : Learn about attacks against passwords and cleartext traffic; explore options for mitigation via SSH and SSL/TLS.
+ [Net Sec Challenge](https://tryhackme.com/room/netsecchallenge) : Practice the skills you have learned in the Network Security module.

### Vulnerability Research
+ [Vulnerabilities 101](https://tryhackme.com/room/vulnerabilities101) : Understand the flaws of an application and apply your researching skills on some vulnerability databases.
+ [Exploit Vulnerabilities](https://tryhackme.com/room/exploitingavulnerabilityv2) : Learn about some of the tools, techniques and resources to exploit vulnerabilities
+ [Vulnerability Capstone](https://tryhackme.com/room/vulnerabilitycapstone) : Apply the knowledge gained throughout the Vulnerability Module in this challenge room.

### Metasploit
+ [Metasploit: Introduction](https://tryhackme.com/room/metasploitintro) : An introduction to the main components of the Metasploit Framework.
+ [Metasploit: Exploitation](https://tryhackme.com/room/metasploitexploitation) : Using Metasploit for scanning, vulnerability assessment and exploitation.
+ [Metasploit: Meterpreter](https://tryhackme.com/room/meterpreter) : Hack your first website (legally in a safe environment) and experience an ethical hacker's job.

### Privilege Escalation
+ [What the Shell?](https://tryhackme.com/room/introtoshells) : An introduction to sending and receiving (reverse/bind) shells when exploiting target machines.
+ [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) : Learn the fundamentals of Linux privilege escalation. From enumeration to exploitation, get hands-on with over 8 different privilege escalation techniques.
+ [Windows Privilege Escalation](https://tryhackme.com/room/windowsprivesc20) : Learn the fundamentals of Windows privilege escalation techniques.

### Introduction to Cyber Security
+ [Offensive Security Intro](https://tryhackme.com/room/offensivesecurityintro) : Hack your first website (legally in a safe environment) and experience an ethical hacker's job. 
+ [Defensive Security Intro](https://tryhackme.com/room/defensivesecurityintro) : Introducing defensive security and related topics, such as Threat Intelligence, SOC, DFIR, Malware Analysis, and SIEM.
+ [Careers in Cyber](https://tryhackme.com/room/careersincyber) : Introducing defensive security and related topics, such as Threat Intelligence, SOC, DFIR, Malware Analysis, and SIEM.

### Network Fundamentals
+ [What is Networking?](https://tryhackme.com/room/whatisnetworking) : Begin learning the fundamentals of computer networking in this bite-sized and interactive module.
+ [Intro to LAN](https://tryhackme.com/room/introtolan) : Learn about some of the technologies and designs that power private networks.
+ [OSI Model](https://tryhackme.com/room/osimodelzi) : Learn about the fundamental networking framework that determines the various stages in which data is handled across a network.
+ [Packets & Frames](https://tryhackme.com/room/packetsframes) : Understand how data is divided into smaller pieces and transmitted across a network to another device.
+ [Extending Your Network](https://tryhackme.com/room/extendingyournetwork) : Learn about some of the technologies used to extend networks out onto the Internet and the motivations for this.

### How The Web Works
+ [DNS in Detail](https://tryhackme.com/room/dnsindetail) : Learn how DNS works and how it helps you access internet services.
+ [HTTP in Detail](https://tryhackme.com/room/dnsindetail) : Learn about how you request content from a web server using the HTTP protocol.
+ [How Websites Work](https://tryhackme.com/room/howwebsiteswork) : To exploit a website, you first need to know how they are created.
+ [Putting it all together](https://tryhackme.com/room/puttingitalltogether) : Learn how all the individual components of the web work together to bring you access to your favourite web sites.

### Linux Fundamentals
+ [Linux Fundamentals Part 1](https://tryhackme.com/room/linuxfundamentalspart1) : Embark on the journey of learning the fundamentals of Linux. Learn to run some of the first essential commands on an interactive terminal.
+ [Linux Fundamentals Part 2](https://tryhackme.com/room/linuxfundamentalspart2) : Continue your learning Linux journey with part two. You will be learning how to log in to a Linux machine using SSH, how to advance your commands, file system interaction.
+ [Linux Fundamentals Part 3](https://tryhackme.com/room/linuxfundamentalspart3) : Power-up your Linux skills and get hands-on with some common utilities that you are likely to use day-to-day!

### Windows Fundamentals
+ [Windows Fundamentals 1](https://tryhackme.com/room/windowsfundamentals1xbx) : In part 1 of the Windows Fundamentals module, we'll start our journey learning about the Windows desktop, the NTFS file system, UAC, the Control Panel, and more..
+ [Windows Fundamentals 2](https://tryhackme.com/room/windowsfundamentals2x0x) : In part 2 of the Windows Fundamentals module, discover more about System Configuration, UAC Settings, Resource Monitoring, the Windows Registry and more..
+ [Windows Fundamentals 3](https://tryhackme.com/room/windowsfundamentals3xzx) : In part 3 of the Windows Fundamentals module, learn about the built-in Microsoft tools that help keep the device secure, such as Windows Updates, Windows Security, BitLocker, and more...

## Other Rooms per Categories



