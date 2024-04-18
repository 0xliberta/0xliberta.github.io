---
title: "eWPTXv2 exam Review"
date: 2024-1-26 00:00:00 +0800
categories: [elearnsecurity]
tags: [INE]
author: hameed
---
# eWPTXv2 Review

**What is** eWPTXv2 **?**

Elearn Web Application Penetration Testing eXtreme is a challenging marathon that closely mimics real-world scenarios where ethical hacking techniques are applied within a limited time frame to solve a security audit problem. The exam is designed to cover OWASP TOP 10 topics and advanced web application penetration testing techniques. It’s not a simulation; instead, it’s a real-world example of a corporate web application, emulated using live virtual machines, networks, and applications, intended to test ethical hacking skills.

**EWPTXv2 Exam Information :**

1. **Exam Price:** The exam voucher costs $400. Keep an eye out for Black Friday deals, as they sometimes offer access to training, labs, and a free $400 voucher for any exam.
2. **Expiration:** Your exam voucher expires after 180 days or 6 months from the purchase date. Plan your preparation and exam schedule accordingly.
3. **Passing Score:** While the main goal is to uncover as many vulnerabilities as possible, there are essential criteria you must meet during the test. Make sure to thoroughly understand these requirements and aim to fulfill them during your exam.
4. **Exam Infrastructure:** Expect to access target applications via a VPN connection. The exam setup closely mirrors a real-world penetration test, so practice navigating and assessing systems in a simulated environment.
5. **Test Duration:** The exam consists of 7 days for testing and an additional 7 days for reporting. Use your time wisely during both phases to conduct thorough assessments and document your findings effectively.

**ِArchitecture :**

There are about 3 subdomains that can be compromised in exam via 2 servers 

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/6813b55c-1487-49c3-8c6c-0971eb165658)

**Goal:** “The goal of the exam is to Get XXE and Get 2 RCE via 2 diffrent technique and 5 sqli and diffrent types of misc vulnerabilities”

# Exam Topics :

1. [SQL Injection](https://portswigger.net/web-security/sql-injection)
2. [Authentication](https://portswigger.net/web-security/authentication)
3. [Directory traversal](https://portswigger.net/web-security/file-path-traversal)
4. [Command Injection](https://portswigger.net/web-security/os-command-injection)
5. [Information Disclosure](https://portswigger.net/web-security/information-disclosure)
6. [Access Control](https://portswigger.net/web-security/access-control)
7. [Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
8. [XXE Injection](https://portswigger.net/web-security/xxe)
9. [Cross-site Scripting (XSS)](https://portswigger.net/web-security/cross-site-scripting)
10. [Cross-site request forgery (CSRF)](https://portswigger.net/web-security/csrf)
11. [Server-side template injection (SSTI)](https://portswigger.net/web-security/server-side-template-injection)
12. [Insecure deserialization](https://portswigger.net/web-security/deserialization)

# Important Topics that can help you to pass eWPTXv2 :

**Evasion techniques**. Some payloads just don’t work and it doesn’t matter how hard you tried or how far you have gotten. This is because filters are in place and you just have to know how to work around them in order to run your exploit properly.


**Scripting**. Scanners are ok, but they can only highlight an issue if there is any. Some vulnerabilities require proper exploitation which can not be done with any available tool. This is because exam machines require custom exploitation tools and the ones off the shelf do not work properly. Luckily for us, there are multiple custom exploitation scripts on the internet that we can tweak a bit and make them run.

**Mapping application**. Since the exam is for web applications, prepare to approach this with no prior knowledge. This means you have to know your way around enumerating or mapping the web. This helps to identify the attack surface and create your own thread model. This is a must since it is not a CTF.

# Exam restrictions :

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/39766aa2-1bdb-4b9b-b13a-719bef729430)


One of the fun parts is there are no restrictions to use any exploitation or scanner tools. This is great since it is very similar to the real-world scenario. This does not mean that there are any CVE’s waiting to be exploited. The exam is prepared in such a way that you have to know how to identify, exploit, and post exploited vulnerabilities that may or not be found in a preparation course for the exam.

# Exam Preparation:

- **Course Content:**
    - Module 1 : Encoding and Filtering
        - Provides a comprehensive understanding of how data is processed and interpreted by web applications.
        - Covers encoding techniques such as base32/64, URL encoding, Unicode, and HTML encoding in detail.
        - Explores filtering mechanisms, including regular expressions (regex), web application firewalls (WAFs), and client-side filters.
        - Offers deep dives into each topic to ensure a thorough understanding beyond surface-level knowledge.
    - Module 2 : Evasion Basics
        - Explores obfuscation techniques in URI, PHP, and JavaScript.
        - Covers non-alphanumeric PHP obfuscation and JavaScript obfuscation in depth.
        - Provides valuable insights into evasion techniques beyond typical encoding methods.
    - Module 3 : Cross-Site Scripting
        - Discusses the prevalence and historical context of XSS attacks.
        - Explores various XSS attack variations and their potential impact.
        - Highlights recent attacks and the wide range of exploitation possibilities with XSS, including cookie grabbing, defacement, phishing, keylogging, and internal port scanning.
    - Module 4 : XSS – Filter Evasion and WAF Bypassing
        - Covers an extensive array of evasion techniques for bypassing sanitization, blacklist filters, and browser security filters.
        - Provides examples of constructing strings using charcode, JS constructors, and other methods to bypass filters.
        - Offers valuable insights into bypassing filters for XSS in event handlers and other scenarios.
    - Module 5 : Cross-Site Request Forgery
        - Provides historical context and basics of CSRF vulnerabilities.
        - Explores attack vectors and techniques for exploiting CSRF mechanisms.
        - Discusses analyzing token entropy and exploiting poor randomness using tools like Burp Sequencer.
    - Module 6 : HTML5
        - Discusses new features introduced in HTML5 and their potential impact on web security.
        - Explores exploitation techniques leveraging HTML5's new tags and functionalities.
    - Module 7 : SQL Injection
        - Covers the fundamentals of SQL injection attacks and their exploitation across various database management systems (DBMS).
        - Introduces advanced techniques such as 2nd Order SQL Injection, demonstrating scenarios where injected payloads are not immediately used.
    - Module 8 : SQLi – Filter Evasion and WAF Bypassing
        - Explores evasion techniques for bypassing keyword and function filters in SQL injection attacks.
        - Covers DBMS gadgets, intermediary characters, strings, integers, and type conversion methods for bypassing filters.
    - Module 9 : XML Attacks
        - Provides a thorough understanding of XML standards and comparisons with HTML.
        - Explores XML tag injection, XML External Entity (XXE) attacks, XPath injections, and their exploitation techniques.
        - Offers valuable insights into discovering and exploiting XML-related vulnerabilities.
    - Module 10 : Attacking Serialization
        - Covers Insecure Deserialization attacks, which are part of the OWASP top 10 attacks.
        - Provides information on identifying possible serialized objects in different languages and exploiting vulnerabilities.
        - Includes labs with four different attacks across Java, PHP, and .NET languages.
    - Module 11 : Server Side Attacks
        - Focuses on server-side attacks like Server-Side Template Injection (SSTI), Server-Side Request Forgery (SSRF), and Server-Side Includes (SSI).
        - Includes challenging labs demonstrating the impact of server-side attacks, particularly Remote Code Execution (RCE).
    - Module 12 : Attacking Crypto
        - Covers crypto attacks, primarily focusing on a dated attack from 2013.
        - Provides basic crypto content for those unfamiliar with cryptographic principles.
        - May not be as interesting for those with extensive experience in cryptanalysis.
    - Module 13 : Attacking Authentication & SSO
        - Explores common authentication methods, including Single Sign-On (SSO) with JWT, OAuth, SAML, and Two-Factor Authentication (2FA).
        - Provides in-depth coverage of these topics.
    - Module 14 : Pentesting APIs & Cloud Applications
        - Covers basic API pentesting, which may not provide new insights for experienced pentesters but serves as a good introduction for beginners.
        - Discusses attacks on cloud applications with real-world examples, such as attacks on S3 Buckets.
    - Module 15 : Attacking LDAP-based Implementations
        - Explores LDAP-based attacks, providing background on how LDAP works and how to manipulate LDAP injection vulnerabilities in web applications.
        - Offers insights into a less commonly discussed attack vector.

---

- **Extra cheese :**
- Focus on only finding these vulnerabilities if your own goal to only pass exam
    - [SQLI](https://portswigger.net/web-security/all-labs#sql-injection)
    - [XXE](https://portswigger.net/web-security/all-labs#xml-external-entity-xxe-injection)
    - [RCE via SSTI](https://portswigger.net/web-security/all-labs#server-side-template-injection)
    - [RCE via SSRF](https://portswigger.net/web-security/all-labs#server-side-request-forgery-ssrf)
    - [RCE via Java serialization](https://portswigger.net/web-security/all-labs#Insecure-deserialization)
    - [Object Serialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
    - [SSRF](https://portswigger.net/web-security/all-labs#server-side-request-forgery-ssrf)
    - [Authorization Bypass](https://portswigger.net/web-security/all-labs#information-disclosure)
    - [World wide XSS](https://portswigger.net/web-security/all-labs#cross-site-scripting)
    ![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/18a34771-2ceb-4e55-8b4c-87a3e6b94a8d)

    

- **Feed Back !** In my opinion, the exam is really good and I found it best in class for the Black Box Pentest Approach. I will highly recommend this certification for anyone who wants to challenge their skills in Black Box Pentest, However, at the same time, I faced stability issues with the Exam Environment. I noticed that you will need multiple resets in order to sometimes gain a successful execution of the exploits.
![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/72d1c4ab-0e19-434a-8e6e-803d51ebfdc4)
