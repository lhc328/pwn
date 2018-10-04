# 2018强网杯--pwn-silent2

题目和silent差不多

checksec

```

```

可以对got表进行写

ida

```c
__int64 sub_4009DC()
{
  size_t size; // [rsp+0h] [rbp-20h]
  unsigned __int64 i; // [rsp+8h] [rbp-18h]
  char *v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  __isoc99_scanf("%lu", &size);
  getchar();
  if ( size != 16 && size <= 0x7F )             // size=16 || size > 0x7f
    exit(0);
  v3 = (char *)malloc(size);
  sub_4008B6(v3, size);
  for ( i = 0LL; i <= 9 && s[i]; ++i )
    ;
  if ( i == 10 )
    exit(0);
  s[i] = v3;
  return 0LL;
}
```

可见题目对堆大小进行限制

```c
signed __int64 sub_400AB7()
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

free依然没有把指针清空。

## 利用思路

double free达到地址任意写，修改free_got为system地址



