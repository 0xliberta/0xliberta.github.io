---
title: "OFFSHORE Lab Review"
date: 2023-11-1 00:00:00 +0800
categories: [HackTheBox]
tags: [ProLabs]
author: essam
---
# OFFSHORE Lab Review

## What is Offshore Lab ?

Offshore Pro Lab is an Active Directory lab that simulates the look and feel of a real-world corporate network. You are an agent tasked with exposing money laundering operations in an offshore international bank. As a real-world penetration tester, you need to assess the external perimeter, gain an internal foothold and pivot across multiple hosts and forests. Users start from an external perspective and have to penetrate the “DMZ” and then move laterally through the CORP.LOCAL, DEV, ADMIN and CLIENT forests to complete the lab. To track progress, there are multiple flags planted along the way as well as a few side challenges not required to advance within the Active Directory environment. Players can submit flags to earn a place in the Offshore Hall of Fame and receive badges for various stages of completion.

## **AV Phase :**

Only Server 2016 and Windows 10 are in use and all machines and AV are patched up to a reasonable level , You will not be able to easily use Frameworks as the AV is actually very up to date and it will not like a lot of the tools that you would want to use. There is also AMSI in place and other mitigations. This means that you'll either start bypassing the AV OR use native Windows tools.

## Estimated Cost**:**

one time $49 or €44. Note that this is a separate fee, that you will need to pay even if you have VIP subscription. Additionally, you do NOT need any specific rank to attempt any of the Pro Labs.

## About the Lab:

*Offshore*, the Pro Lab on Hack The Box, is a complex and immersive cybersecurity training experience that pushes participants to navigate through 21 machines and 38 flags distributed across 4 distinct domains. The lab challenges users to pivot between systems, requiring strategic planning and meticulous post-exploitation techniques.

One of the standout features of *Offshore* is its depth. With scenarios where users find themselves several pivots deep and nested within multiple RDP sessions, the lab tests not only technical skills but also resilience and problem-solving abilities. While the challenges might occasionally feel daunting, the experience is designed to be manageable with proper post-exploitation methodologies.

A notable aspect of the lab is its emphasis on a single intended path for each box. This approach ensures that participants are guided through specific techniques and methodologies, allowing for a structured learning experience. By following the intended paths, users can gain a deep understanding of various penetration testing strategies and methodologies.

The diversity of domains and the requirement for pivoting create a realistic simulation of complex real-world scenarios, making *Offshore* a valuable training ground for aspiring cybersecurity professionals. Participants can expect to encounter a wide array of challenges, ranging from basic to advanced, thereby enhancing their skills across different proficiency levels.

It's important to note that while the lab presents challenges that can occasionally feel overwhelming, it also provides an opportunity for individuals to refine their skills in post-exploitation techniques, lateral movement, and privilege escalation. Additionally, the lab's structure encourages users to utilize a variety of tools and methodologies, fostering a well-rounded skill set.

In summary, *Offshore* Pro Lab on Hack The Box offers a rigorous and engaging experience for cybersecurity enthusiasts seeking to enhance their penetration testing skills. With its intricate scenarios, structured paths, and emphasis on proper post-exploitation, the lab provides a valuable learning opportunity for individuals looking to excel in the field of cybersecurity.

## Architecture:

There are about 21 Machine that can be compromised in the lab with 4 different domains (CORP.LOCL, DEV, ADMIN, CLIENT)

Goal: The goal of the lab is to reach Domain Admin and collect all the flags.

## What the lab covers ?

- Web Application Attacks
- Enumeration
- Exploiting Obscure and Real-World Active Directory Flaws
- Local Privilege Escalation
- Lateral Movement and Crossing Trust Boundaries
- Evading Endpoint Protections
- Reverse Engineering
- Out-Of-The-Box Thinking

## Lab Requirements:

- Basic of Web Application Attacks.
- Working Knowledge of Active Directory Attacks.
- Strong Knowledge of network penetration testing and you should be aware with used tools.
- Working Knowledge of Active Directory Attacks.
- Working Knowledge of Antivirus Bypass techniques
- Strong Knowledge of Windows Privilege Escalation
- Basic Knowledge of Ad Persistence

# **Lab** **Topics:**

Before diving into the topics in the lab, it is important to understand:

## **What Is Red Teaming ?**

Red Team Operations, often referred to as Red Teaming, is a cybersecurity practice where a group of skilled professionals, known as the Red Team, simulates realistic cyberattacks on a system, network, or organization. The primary objective of a Red Team engagement is to identify vulnerabilities and weaknesses in the security posture of the target, by using tactics, techniques, and procedures (TTPs) similar to those used by real-world attackers. Here are some key aspects of Red Team Operations:

### **1. Difference Between Red Team Engagement and Other Security Testing Types:**

- **Penetration Testing:** Penetration testing involves simulating cyberattacks to evaluate a system's security. However, it typically focuses on finding and exploiting known vulnerabilities.
- **Vulnerability Assessment**: This is a broader approach that identifies and classifies vulnerabilities in a system. Unlike Red Teaming, it might not involve active exploitation.

### **2. Methodology of Red Team:**

- **Reconnaissance**: Gathering information about the target to understand its infrastructure, employees, and potential vulnerabilities.
- **Scanning and Enumeration**: Identifying live hosts, open ports, and services running on the target network. Exploitation: Actively exploiting vulnerabilities to gain access to systems or sensitive information.
- **Post-Exploitation**: Maintaining access, escalating privileges, and performing lateral movement within the network.
- **Reporting**: Documenting findings, vulnerabilities exploited, and recommendations for improving security.

### **3. Red Teaming Operations Modules:**

- **Social Engineering:** Simulating phishing attacks, impersonation, or other methods to manipulate people into revealing sensitive information.
- **Physical Security:** Assessing the physical security measures in place, including access controls, surveillance, and security personnel effectiveness.
- **Network Security**: Evaluating firewalls, intrusion detection/prevention systems, and other network security measures.
- **Application Security:** Assessing the security of web applications, APIs, and other software solutions.
- **Wireless Security:** Identifying vulnerabilities in wireless networks, such as Wi-Fi encryption weaknesses.

### **4. Key Components and Activities:**

- **Threat Emulation:** Red Teams emulate real-world threat actors to provide a realistic assessment of an organization's security posture.
- **Scenario-Based Testing**: Red Team engagements often involve simulating specific attack scenarios, like advanced persistent threats (APTs), to test the organization's response capabilities.
- **Continuous Testing:** Red Team operations are not one-time events.
- Regular testing helps organizations stay ahead of evolving threats and vulnerabilities.

### **5. Helpful Details:**

- **Legal and Ethical Considerations**: Red Team activities must be conducted within legal and ethical boundaries. Organizations need to ensure they have explicit permission to test and exploit systems.
- **Collaboration**: Red Team operations often involve collaboration with the organization's Blue Team (defenders) to enhance detection and response capabilities.
- **Training and Skill Development**: Red Team professionals require diverse skills, including programming, exploit development, and in-depth knowledge of various operating systems and applications.

## Enumeration:

You have to learn about enumeration very well cause its the first phase of your pentest which is like the home essentials. So, if you didn’t enumerate well you gonna miss a lot of things and maybe your pentest fails. Some resources for enumration:

- https://www.youtube.com/watch?v=WvSEkPU1n0I
- https://www.youtube.com/watch?v=947o1ySWU2w
- don’t forget to do more search about enumeration

## Web Applications Attacks:

You have to learn how to do enumeration & exploit common web applications vulnerabilities such as OWASP top 10. Some Resources for web applications pentesting:

- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README
- https://owasp.org/www-project-top-ten/
- https://portswigger.net/web-security/all-topics
- don’t forget to do more search

## **Password Cracking & Brute Forcing:**

Password cracking means recovering passwords from a computer or from data that a computer transmits. This doesn’t have to be a sophisticated method. A brute-force attack where all possible combinations are checked is also password cracking.

If the password is stored as plaintext, hacking the database gives the attacker all account information. However, now most passwords are stored using a key derivation function (KDF). This takes a password and runs it through a one-way encryption cipher, creating what’s known as a “hash.” The server stores the hash-version of the password.

It’s easy to try different hashed passwords at a high rate when using a GPU or botnet. That’s why most password hash functions use key stretching algorithms, which increase the resources (and, therefore, time) needed for a brute-force attack.

Some methods of password cracking become significantly more difficult if your password uses salting or key stretching. Unfortunately, there are still some services that store unencrypted or weakly-encrypted passwords on their servers.

**Resources:**

- [https://www.youtube.com/watch?v=XjVYl1Ts6XI](https://www.youtube.com/watch?v=XjVYl1Ts6XI&ab_channel=HackerSploit)
- [https://www.youtube.com/watch?v=z4_oqTZJqCo](https://www.youtube.com/watch?v=z4_oqTZJqCo&ab_channel=NetworkChuck)
- https://www.youtube.com/watch?v=nNvhK1LUD48&ab_channel=JohnHammond
- https://www.freecodecamp.org/news/crack-passwords-using-john-the-ripper-pentesting-tutorial/
- don’t forget to do more search

## Initial Access:

At this stage we use various entry vectors to gain an initial foothold within a network. We can do that in multiple ways like Exploit Public-Facing Applications, Zero-Day Vulnerabilities , CVE’s.

we be focus on products cve’s and Zero-Day Vulnerabilities, such as Splunk cve’s.

there’re many poc’s for this cve such [splunk shell](https://github.com/TBGSecurity/splunk_shells) to get [meterpreter shell](https://www.n00py.io/2018/10/popping-shells-on-splunk/).

# **Active Directory environment:**

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
- **Active Directory Exploitation Phase** !
Now that we have all the information about our AD environments, such as users, computers, groups, and members, shares, OUI, GPO, ACLs, domains, and domain forests. It's time to start exploiting!! There must be a [checklist for AD misconfiguration](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet) when you are in an AD environment. The most common attacks discussed in The Lab include:
- [Kerberos](https://www.simplilearn.com/what-is-kerberos-article) Attacks
![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/568a54aa-4ed8-429d-90e0-083e56a65327)


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
- **Resources:**

Active directory is widely used by companies so you must know how to pentest it. Some Resources for activce directory pentesting:

- https://www.youtube.com/playlist?list=PLAC2CBE898D01029E
- https://www.youtube.com/playlist?list=PLCLxMnnAnGinh7JKcV3dBnTDW8dhNG96N
- https://www.youtube.com/playlist?list=PLziMzyAZFGMf8rGjtpV6gYbx5hozUNeSZ
- https://adsecurity.org/
- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
- https://github.com/infosecn1nja/AD-Attack-Defense
- https://www.youtube.com/watch?v=IJ4M2DDMjgY
- https://www.youtube.com/watch?v=ELimzgVr3To
- [https://www.youtube.com/watch?v=mcuNn7q8nuY](https://www.youtube.com/watch?v=mcuNn7q8nuY&ab_channel=SemiYulianto)
- https://github.com/mubix/post-exploitation-wiki
- https://pentestlab.blog/category/post-exploitation/
- don’t forget to do more search

# **Conclusion:**

In the realm of unwavering dedication and relentless determination, I emerge triumphant from the intricate challenges of Offshore, the formidable prolab offered by HackTheBox. My goals were sharply defined: to fortify my expertise in Active Directory, sharpen my pivoting skills, and unravel the complexities of employing a C2 framework. Astonishingly, I not only met but surpassed these ambitions, relentlessly pushing my boundaries and embracing the intricacies of internal network pentesting. Amidst the demands of a full-time job, I dedicated every spare moment to mastering Offshore's challenges, immersing myself wholly in this immersive learning odyssey.

My decision to invest personal funds in Offshore underscored my unwavering passion for continuous learning and self-improvement. Throughout this arduous journey, I meticulously honed my skills, refined my approach, and emerged triumphant with a wealth of practical knowledge and an overwhelming sense of accomplishment. Harnessing the prowess of tools like Metasploit, I discovered innovative solutions, saving invaluable time and enhancing my efficiency in navigating the labyrinthine challenges.

This achievement stands as a resounding testament to my unwavering resilience, unmatched adaptability, and unquenchable thirst for knowledge within the ever-evolving realm of cybersecurity. Reflecting on this transformative odyssey, I am not only deeply grateful for the invaluable skills acquired but also invigorated by the boundless opportunities that await in my continuous professional growth.

This long-overdue review comes a month and a half after my completion of the Offshore lab. Amidst the chaos of work, life, and the unpredictable challenges of these times, finding the opportunity to write this review took longer than anticipated. Towards the end of 2022, after successfully completing the CRTP course, I took a hiatus from formal courses and labs. Instead, I dedicated my time to revisiting my notes and reinforcing the knowledge I had gained. However, as 2023 began, I realized my lack of recent experience in infrastructure assessments. My professional life had predominantly involved web application testing, and I felt the need to venture back into the realm of network assessments.

With a solid foundation from my prior achievements, including the OSCP, CRTP, CRTE Courses, occasional exploits of VulnHub and HTB boxes, and a full-time role as a pentester, I felt adequately prepared for a new challenge. After researching various options, I chose Offshore from HTB's pro-labs. Its reputation as a realistic "corporate" environment and its intermediate rating intrigued me. Despite my confidence, I embarked on this journey in September 2023, eager to explore Offshore and further enhance my skills. My experience with Offshore solidified my belief that HTB's Pro Labs are among their most outstanding content offerings, making them my personal favorite, and finally I recommend you search for the Flags everywhere and don’t forget to try to use flags as a password😉
![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/4f422f52-da7e-402d-9e49-3ea834124360)
