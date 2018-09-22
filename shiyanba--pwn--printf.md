# shiyanba--pwn--printf

ida打开，32位的题

```
setbuf(stdout, 0);
ask_username(&s1);
ask_password(&s1);
```

```c++
char *__cdecl ask_username(char *dest)
{
  char src[40]; // [esp+14h] [ebp-34h]
  int i; // [esp+3Ch] [ebp-Ch]

  puts("Connected to ftp.hacker.server");
  puts("220 Serv-U FTP Server v6.4 for WinSock ready...");
  printf("Name (ftp.hacker.server:Rainism):");
  __isoc99_scanf("%40s", src);
  for ( i = 0; i <= 39 && src[i]; ++i )
    ++src[i];
  return strcpy(dest, src);
}

int __cdecl ask_password(char *s1)
{
  if ( strcmp(s1, "sysbdmin") )
  {
    puts("who you are?");
    exit(1);
  }
  return puts("welcome!");
}
```

有层验证用户名的代码，用户名是 sysbdmin ，我们输入的字符会自动加一，那我们先输入减一的进去，即rxraclhm

进入主程序，我们可以输入get,put,dir进行不同的操作

- put：生成一个文件，自定义文件名跟内容
- get: 根据输入的文件名，打印对应内容
- dir: 可以打印所有文件名，最后输入的文件名在最前面，而且两个文件名“无缝衔接”

get_file函数里面可以看到存在格式化字符串漏洞

```c++
int get_file()
{
  char dest; // [esp+1Ch] [ebp-FCh]
  char s1; // [esp+E4h] [ebp-34h]
  char *i; // [esp+10Ch] [ebp-Ch]

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 40);
      return printf(&dest);   //漏洞
    }
  }
  return printf(&dest);
```

### 格式化字符串：

当我们输入printf可识别的格式化字符串时，printf会将其作为格式化字符串进行解析并输出。原理很简单，形如printf(“%s”,“Hello world”)的使用形式会把第一个参数%s作为格式化字符串参数进行解析，在这里由于我们直接用printf输出一个变量，当变量也正好是格式化字符串时，自然就会被printf解析。

输出的内容正好是esp-4开始往下的一连串数据。所以理论上我们可以通过叠加%x来获取有限范围内的栈数据。

## 利用思路

### 第一步 计算格式化字符串的偏移

### 第二步 构造 /bin 和 /sh文件

### 第三步 将system地址放在puts_got地址处