# 2018网鼎杯--pwn--blind

题目有三个功能 new change  release 没有提供show，是真瞎啊，瞎子退团吧，我奶不动你

```

```

checksec：

```

```

没开pie。

打开ida查看：

```c++
unsigned __int64 newnote()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(&s, 0, 0x10uLL);
  read(0, &s, 0xFuLL);
  v1 = atoi(&s);
  if ( v1 <= 5 && !ptr[v1] )                    // 新建不超过6个
  {
    ptr[v1] = malloc(0x68uLL);                  // 固定大小为0x68
    printf("Content:", &s);
    sub_400932((__int64)ptr[v1], 0x68u);        // 输入范围再0x68以内
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

```c++
unsigned __int64 release()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(&s, 0, 0x10uLL);
  read(0, &s, 0xFuLL);
  v1 = atoi(&s);
  if ( v1 <= 5 && ptr[v1] && dword_602098 <= 2 )
  {
    free(ptr[v1]);
    ++dword_602098;                             // 指针没清空
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

可见release没有把指针清空，存在uaf，且块不能新建超过6块，每块规定大小为0x68。

除此之外，我们还发现system的函数。

```c++
int sub_4008E3()
{
  return system("/bin/sh");
}
```



## 利用思路

- 通过uaf拿到bss段地址

- 修改存放在bss上的file指针

  新知识：伪造_IO_FILE结构体

  由于可以在bss段上任意写，所以修改ptr为bss地址，并在bss上伪造stdout的_IO_FILE结构体并伪造一个vtable将原本printf的虚表地址变成后门地址，让stdout地址指向这个结构体，当调用到vtable就可以执行后门函数

  我们平常在应用程序中调用fclose、fputs这些函数的时候系统最终都会通过_IO_jump_t这个函数表指针对函数进行调用（如fclose会调用close函数等）。

  在知道了这一点后，试想如果我们想办法利用其他各种溢出方式覆了应用程序的文件指针，使其指向我们可控区域，在该区域伪造相应的_IO_FILE_plus头（主要是_IO_jump_t表或者是表中函数的指针），最终在程序调用fclose函数或其它函数的时候，就可以控制程序去执行我们想要它执行的地址，control the eip, control the world。

  比较常见的是利用strcpy，strcat等覆盖了文件指针然后进一步利用。

  (参照https://www.anquanke.com/post/id/84987)

