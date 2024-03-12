---
title: "Rasta Labs Review"
date: 2023-1-26 00:00:00 +0800
categories: [HackTheBox]
tags: [ProLabs]
---
# Rasta Lab Review

**What is Rasta Lab ?** 

Rasta Labs is a virtual Red Team Simulation environment, designed to be attacked as a means of learning and honing the skills the team’s utilizes on missions. The lab is focused on operating within a Windows Active Directory environment where members must gain a foothold, elevate their privilege, be persistent and move laterally to reach the goal of Domain Admin. RastaLabs is designed to simulate a typical corporate environment, based heavily on Microsoft Windows systems. Elements include Active Directory (with a Server 2016 functional domain level), Exchange, Internet Information Services, SQL Server, and Windows 10 workstations. Machines are also segregated across multiple subnets.

**AV Phase :** 

Only Server 2016 and Windows 10 are in use and all machines and AV are patched up to a reasonable level , You will not be able to easily use Frameworks as the AV is actually very up to date and it will not like a lot of the tools that you would want to use. There is also AMSI in place and other mitigations. This means that you'll either start bypassing the AV OR use native Windows tools.

**Price:**
 one time £70 setup fee + £20 monthly. Note that 
this is a separate fee, that you will need to pay even if you have VIP 
subscription. Additionally, you do NOT need any specific rank to attempt
 any of the Pro Labs.

**ِArchitecture :**

There are about 15 servers that can be compromised in the lab with only one domain.

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/453c5d73-7c90-4ad6-8565-ea8ad7f66f58)


**Goal:**
 "The goal of the lab is to reach Domain Admin and collect all the flags."

# Important Topics that can help you :

- **[What is Red Team Operation ?](https://www.hackingarticles.in/guide-to-red-team-operations/)** 
Before diving into the topics in the lab, it is important to understand what is a Red Team engagement. Therefore, we should firstly know the difference between Red Team Engagement and other security testing types , Methodology of Red Team , Red Teaming Operations Modules and more helpful details .
- OSINT !
This is the most important  phase for red teamers. During this phase you must collect all relevant information about your target, including usernames, email addresses, leaks of passwords, etc.
We can use [OSINT Frame Work](https://osintframework.com/) To get some Information about our Target .
- Initial Access !
At this stage we use various entry vectors to gain an initial foothold within a network. We can do that in multiple ways like Exploit Public-Facing Applications, Zero-Day Vulnerabilities , Valid Accounts and Social Engineering including removable media and phishing. We will be focusing on Phishing with OWA . There are many different types of phishing, such as [Phishing with Microsoft Office](https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office) , [Spear Phishing Links](https://dmcxblue.gitbook.io/red-team-notes/initial-acces/spear-phishing-links) Including [HTA Files](https://dmcxblue.gitbook.io/red-team-notes/initial-acces/spear-phishing-links/tools) , [Binaries](https://dmcxblue.gitbook.io/red-team-notes/initial-acces/spear-phishing-links/binaries) and [PDF Files](https://dmcxblue.gitbook.io/red-team-notes/initial-acces/spear-phishing-links/pdf). All of these techniques are used after recon to employs emails and on OSINT stage. We can use [Kerbrute](https://www.hackingarticles.in/a-detailed-guide-on-kerbrute/) to enumerate valid Active Directory user accounts and Emails . Also, this tool can be used for password attacks such as password bruteforce, username enumeration, password spray etc.
- Enumeration On Active Directory environment !
Once you get into a network, you must enumerate More and more about what?!
Domain Computers, Groups, ACLs, Services, Processes, etc. 
We do that to try to get a high privilege .
Here is a list of some of the windows [automated tools](https://www.hackingarticles.in/window-privilege-escalation-automated-script/) for enumerating information .
In our case we can't execute any binaries because of AV, so we will use powershell to Enum [Powershell is a very important thing for red teamers](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters). All of these tasks can be handled with Powershell
Also we have a [Bloodhound Tool](https://www.hackingarticles.in/active-directory-enumeration-bloodhound/). [BloodHound](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html) is programmed to generate graphs that reveal the hidden and relationships within an Active Directory Network. With BloodHound, Attackers can identify complex attack paths that would otherwise be impossible.
How can we run these scripts with Bypass AV?!
- PowerShell Security !
- [Execution Policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.3)
PowerShell's execution policy is a safety feature that controls the conditions under which PowerShell loads configuration files and runs scripts. This feature helps prevent the execution of malicious scripts.
We should [bypass it](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) first so that we can run our powershell scripts

- [PowerShell Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
PowerShell's Constrained Language (CLM) mode limits the functionality available to users to reduce the attack surface
. It is meant to be used in conjunction with application control solutions like Device Guard User Mode Code Integrity
We can't run anything in this mode, we must [bypass it](https://github.com/padovah4ck/PSByPassCLM) firstly
- [Anti-Malware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
The Windows Antimalware Scan Interface (AMSI) is a versatile interface standard that allows your applications and services to integrate with any antimalware product that's present on a machine. AMSI provides enhanced malware protection for your end-users and their data, applications, and workloads
This is another security restriction we should [bypass](https://www.hackingarticles.in/a-detailed-guide-on-amsi-bypass/) so that we can run our enumeration and exploitation scripts.

- [PowerShell with Applocker](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/use-the-applocker-windows-powershell-cmdlets) 
Windows AppLocker lets administrators control which executable files are denied or allowed to be run. With this policy, administrators are able to generate rules based on file names, publishers or file locations on unique identities of files and specify which users or groups can execute those applications.
We saw that there is a security layer that prevents scripts from being executed, so you should [Bypass it](https://www.hacking-tutorial.com/hacking-tutorial/how-to-bypass-windows-applocker/) to complete your mission.
By the way, here is some of the extra cheese about [window security control](https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs) that might be delicious !!
- **Active Directory Exploitation Phase** !
Now that we have all the information about our AD environments, such as users, computers, groups, and members, shares, OUI, GPO, ACLs, domains, and domain forests. It's time to start exploiting!! There must be a [checklist for AD misconfiguration](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet) when you are in an AD environment. The most common attacks discussed in The Lab include:
- [Kerberos](https://www.simplilearn.com/what-is-kerberos-article) Attacks

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/cbe8e37b-a8f2-434f-844b-6e12fef74381)


As we saw, Kerberos Protocol use Tickets ( TGT and TGS ) on authentication, , so Is there a way retrieve a user's hashes or Application Services hashes?
 *The answer is yes , An attack can retrieve the user hashes that can be brute-forced offline and that's called [AS-REP Roasting](https://www.hackingarticles.in/as-rep-roasting/) Attack . but if we have to play with Applications services we can do [Kerberoasting](https://www.hackingarticles.in/deep-dive-into-kerberoasting-attack/) attack*

- [Abusing Active Directory ACLs/ACEs](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse)
Active Directory objects such as users and groups are securable objects and DACL/ACEs define who can read/modify those objects ( change account name, reset password, etc). Our Goal is  abuse these ACLs.
 There are common ACLs we can abuse it to get high privilege or use it to Letral movement.
GenericAll : full rights to the object (add users to a group or reset user's password)
GenericWrite: update object's attributes (i.e logon script)
WriteOwner: change object owner to attacker controlled user take over the object
WriteDACL : modify object's ACEs and give attacker full control right over the object
AllExtendedRights : ability to add user to a group or reset password
ForceChangePassword : ability to change user's password
[Read LAPS Password](https://www.hackingarticles.in/credential-dumpinglaps/) : can read the LAPS password of the computer account this ACE applies to
****ReadGMSAPassword :  can read the GMSA password of the account this ACE applies to

As I mentioned that there are many attacks on the AD eviroment, such as **[Exploit Group Policy Objects GPO](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#exploit-group-policy-objects-gpo)**, [Delegating attacks](https://www.hackingarticles.in/domain-escalation-resource-based-constrained-delegation/), [Trust Abuse MSSQL Servers](https://github.com/drak3hft7/Cheat-Sheet---Active-Directory#trust-abuse-mssql-servers), [Active Directory Certificate Services Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#active-directory-certificate-services) , etc .

These topics are more advanced, so I think it will be in another labs like [Cybernetics](https://www.hackthebox.com/home/labs/pro/view/3) or [APT](https://www.hackthebox.com/home/labs/pro/view/5) Labs , but you can get a quick overview of them on [AMAZING AD ATTACKS METHDOLOGY](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

- **Post Exploitation Phase !**
- [Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)
****After u get a high privilege on the server u need to do some of  [Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md) and Letral movement techniques .
 let's start with Persistence technique :
Before we do some of the persistence techniques such as dump credentials we have to [turn off Windows Defender](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md#disable-windows-defender) so we can execute binaries like [mimikatz](https://www.hackingarticles.in/understanding-guide-mimikatz/).
We can [dump passwords and hashes in many ways](https://www.hackingarticles.in/password-dumping-cheatsheet-windows/). For example, we can perform mimikatz to get clear password and hashes , [DCSync Attack](https://www.hackingarticles.in/credential-dumping-dcsync-attack/) if we have a high privilege on Domain Controller , use winpease to retrieve saved credentials on RDP or [Auto-logon password](https://www.hackingarticles.in/credential-dumping-windows-autologon-password/) , Dump Interesting process to retrieve a credentials like [LSA|LSASS.EXE](https://www.hackingarticles.in/credential-dumping-local-security-authority-lsalsass-exe/), FireFox or [Application In general](https://www.hackingarticles.in/credential-dumping-applications/)  to get saved credentials ,etc .  the last but not least we can impersonate users on an AD domain by abusing Kerberos authentication. This is called [Golden Ticket Attack](https://www.hackingarticles.in/domain-persistence-golden-ticket-attack/) . 
Those techniques are used to maintain persistence in the network. In addition [Silver ticket Attack](https://www.hackingarticles.in/domain-persistence-silver-ticket-attack/)  that can be used to maintain persistence on a compromised system connected to an Active Directory enterprise domain. This will happen after crafting TGS and tickets for other service.

- Lateal movement 
Once we have the credentials and hashes, it's time to move on!!
In this stage, your objective will be to move from the current server to another one By using credentials we have, we can perform the credentials reuse attack, but how do I use these credentials to move? 
How can I use these credentials to move? It is possible to move by using open protocols and services, the [most common methods](https://www.hackingarticles.in/lateral-movement-remote-services-mitret1021/) are RDP , [WMI](https://www.hackingarticles.in/lateral-movement-wmi/) , PsExec , ssh, [CrackMapExec](https://www.hackingarticles.in/lateral-moment-on-active-directory-crackmapexec/) , etc. The most common tools and protocols support [pass the hash attacks](https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/), which allow you to login not just using passwords, but also by using hashes.
You can attempt to compromise all computers on the network by abusing the server service, the ACLs, and everything else.

****
- **Extra cheese !** 

- [Password cracking](https://www.hackingarticles.in/wordlists-for-pentester/) 
In this section we will crack the hashes we have got to get the clear passwords. We already have a wordlists and can use them like [Rockyou](https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt.gz) and [SecList](https://github.com/danielmiessler/SecLists) But in another situation we need to create specific wordlist dependinging on our target , so we can use [Cewl](https://www.geeksforgeeks.org/cewl-tool-creating-custom-wordlists-tool-in-kali-linux/) , [Crunch](https://www.hackingarticles.in/a-detailed-guide-on-crunch/) and [KwProcessor](https://github.com/hashcat/kwprocessor) that  can be used to creat an Keymap Walking Password Wordlists

- [Pivoting](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md) 
Pivoting is a method of accessing a machine that we have no way of accessing, through an intermediary. The attacker compromises a visible server and then pivots using the compromised server to attack other clients from within the network.

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/91867d68-5bc6-4d72-a85a-cec5ef86fb98)


 there are many techineqes For Pivoting By using [SSH](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md#ssh) , [Metasploit](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md#metasploit) , [sshutel](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md#sshuttle) , [chisel](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md#chisel) , etc . 

- [Port Forwarding](https://www.coeosolutions.com/news/what-is-port-forwarding) 
Port forwarding, or port mapping, allows remote servers and devices on the internet to access the devices that are within your private local-area network (LAN)

We can use different ways to do this task like Metasploit , SSH , Chiesl , sshutle , etc.
Here is the [awoasme cheat sheet](https://www.hackingarticles.in/port-forwarding-tunnelling-cheatsheet/) for different methods of port forwarding

- **Feed Back !** 
In my opinion, this lab is very helpful for anyone who wants to learn some of the Red Team's techniques. As well as OSINT, phishing, and Active Directory attacks, one thing I noticed in the lab is that it sometimes tends to be CTF Style, so I recommend you search for the Flags everywhere.
![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/9748f88e-597e-4e69-b0df-d1d75bb2068d)
