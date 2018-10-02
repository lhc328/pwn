# 2018强网杯--pwn-silent

checksec

```

```

nx 栈溢出检测，估计是堆溢出

ida打开

```
switch ( v3 )
    {
      case 2:
        freenote();
        break;
      case 3:
        update();
        break;
      case 1:
        add();
        break;
    }
```

free函数有漏洞

```c
signed __int64 sub_400A99()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  __isoc99_scanf("%d", &v1);
  getchar();
  if ( v1 < 0 || v1 > 9 )
    return 0xFFFFFFFFLL;
  free(s[v1]);
  return 0LL;
}
```

可以看到指针free后并没有置null 还有.bss段里的指针值也没清0，并且update时没有检测指针是否free

所以uaf 和 fastbin 的double free 都是可以用的

函数中还有system 函数

```
.plt:0000000000400730 ; int system(const char *command)
.plt:0000000000400730 _system         proc near               ; CODE XREF: sub_4009A4+1C↓p
.plt:0000000000400730                 jmp     cs:off_602030
.plt:0000000000400730 _system         endp
```

## 利用思路：

利用uaf修改free的got表为system的地址



