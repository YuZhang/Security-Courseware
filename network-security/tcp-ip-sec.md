#TCP/IP安全

###哈尔滨工业大学 网络与信息安全 张宇 2016

---

阅读材料：[A Look Back at “Security Problems in the TCP/IP Protocol Suite” (ACSAC 2016)](supplyments/TCP-IP-Sec.pdf)

作者Steven M. Bellovin在15年前（1989年）撰写了一篇关于TCP/IP协议族安全问题的论文。在2004年，撰写本文以反思之前的分析是对是错。

本节课学习这些安全问题，并了解一些最近的进展。

##1. TCP序列号预测

###初始序列号猜测攻击

参考资料： [RFC6528: Defending against Sequence Number Attacks (2012)](https://tools.ietf.org/html/rfc6528)
 
- 客户端C与服务器S之间正常TCP三次握手：

```
C——>S :                  SYN(ISN_C)         —————> +——————+
S——>C :   <————   SYN(ISN_S), ACK(ISN_C+1)         |Server|
C——>S :                  ACK(ISN_S+1)       —————> +——————+
```

- 攻击者X伪装为可信主机T与服务器S通信：

```
X——>S :            SYN(ISN_X), SRC=T        —————> +——————+
S——>T :   <————    SYN(ISN_S), ACK(ISN_X+1)        |Server|
X——>S :            ACK(ISN_S+1), SRC=T      —————> +——————+
```

- 如何猜测序列号`ISN_S`？

	- 最早的TCP协议标准RFC793中，为减少旧连接中的分段被新连接接收的几率，建议全局32比特ISN生成器以1/4ms的速度单调递增
	- 若攻击者先连接一次并观察`ISN_S`，就可以已很高的可信度来预测下一次连接的`ISN_S'`
	- 1985年，Morris首次描述了通过预测TCP初始序列号ISN来伪装成一台受害主机，可攻破基于IP地址的访问控制/认证服务，例如Berkeley的rlogin和rsh （目前已被废弃）

- 如何防御这一攻击？

	- 简单的随机化ISN尽管会避免这一攻击，但许多协议栈实现都依赖ISN单调递增规律来用启发式方法区分新旧分段
	- 一种方法是在随机化ISN的同时，要记录旧连接信息，但会增加系统状态
	- RFC6528方案：
		- `ISN = M + F(sip, sport, dip, dport, secretkey)`
		- `M`是4ms计时器，`F()`是一个伪随机函数（密码学哈希函数）
		- `secretkey`在重启时、一段时间后、充分使用后，需更换
		- 攻击者先连接一次获得的ISN用处不大，因为`sip`和`sport`与受害者不同

###Blind In-Window Attacks

####在传统TCP上的攻击

```
 +—————+      +—————+      +—————+     
 |SPORT|—————>|SEQ# |—————>|ACK# |
 +—————+      +—————+      +—————+
    |            |            |
    v            v            v
 exists?       Reset       Hijacking
```

攻击者向一个TCP连接插入报文来打断连接或注入恶意数据:

- 攻击者知道TCP四元组（主要是源端口`SPORT`），实施SYN攻击，重置连接
- +额外知道落在接收窗口内的序列号`SEQ#`，实施RST攻击，重置连接
- ++额外知道ACK号`ACK#`，实施DATA攻击注入数据
- 上述攻击可能实现，因为许多TCP长连接，例如BGP会话，的四元组较易被猜测，且高带宽延迟乘积连接的接收窗口范围很大

####RFC5961的防御方案：

参考资料：[RFC5961: Improving TCP's Robustness to Blind In-Window Attacks (2010)](https://tools.ietf.org/html/rfc5961))

```
———————————————————————————————————————————————         
SEQ#  | Out-of-Win| In-Window |   
———————————————————————————————
      |      ACK  |   Reset   |  Before RFC5961
SYN   —————————————————————————
      |    C-ACK  |   C-ACK   |   After RFC5961
———————————————————————————————————————————————

—————————————————————————————————————————————           
SEQ#  | Out-of-Win|   Exact   |   In-Window
—————————————————————————————————————————————           
      |    Drop   |         Reset
RST   ———————————————————————————————————————
      |    Drop   |   Reset   |   C-ACK
—————————————————————————————————————————————           

—————————————————————————————————————————————
                  |       In-Apt-Win
ACK#  | Out-of-Win| In-Apt-Win| Challenge-Win
—————————————————————————————————————————————           
      |   Drop    |        Process     
DATA  ———————————————————————————————————————           
      |   Drop    |  Process  |   C-ACK
—————————————————————————————————————————————
```

- 挑战ACK包（C-ACK）：确认是否真的发送方
- **当接收到一个SYN包时，发送一个C-ACK包（确认是否真的新连接）**
- 当接收到一个RST包时，
	- 若序列号恰好为下一个待接收序列号(`RCV.NXT`)，则重置连接
	- **若序列号在窗口内但不是RCV.NXT，则发送一个C-ACK包**
		- 对于合法发送方，根据挑战ACK号应答一个序列号正确的RST包
		- 对于攻击者，不会接收到挑战包，也就无法正确应答
	- 若序列号在接收窗口外，则丢弃
- 当接收到一个DATA包时，从原接收窗口中划分出一个挑战窗口，减小了接收窗口
	- 若`ACK#`在接收窗口内，则处理数据包
	- **若`ACK#`在挑战窗口内，则发送C-ACK包**
	- 若接收+挑战窗口（原接收窗口）外，则丢弃 
- **为避免挑战ACK机制占用过多资源，设定单位时间内挑战ACK包数上限**

####基于全局速率限制的攻击技术

参考资料：[Off-Path TCP Exploits: Global Rate Limit Considered Dangerous (USENIX Security 2016)](supplyments/tcp-hijacking.pdf) [[online]
(https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/cao)]

**TCP旁路漏洞（CVE-2016-5696）**：Linux 3.6+（2012年9月发布）中全局系统变量C-ACK包数上限缺省为100/秒

```
                1 C-ACK
Sender     <———————————————    Reciever
                               /   ^
                     99 C-ACK /   /
           Attacker  <———————/   /
                    \———————————/
                    100 bad packets
```

- 为利用每秒C-ACK包数上限的漏洞，下面每步攻击需在单位时间窗口内进行，因此预先与接收者的秒对齐，具体方法略。
- 攻击步骤1：推测两点间是否有连接，即确定`SPORT`
	1. 攻击者以发送方为源地址，以`SPORT`为源端口，发送一个SYN包
		- 若有连接，即SPORT猜测正确，则接收方发送一个挑战ACK包
		- 否则，攻击包被丢弃
	- 攻击者以自己为源地址，发送100个RST攻击包
		- 若有连接，则攻击者观察到99个挑战ACK包，因为之前已经用掉一个
		- 否则，攻击者观察到100个挑战ACK包
- 攻击步骤2：推测`SEQ#`，与步骤1原理类似，但发送的是RST包
	1. 以发送方为源地址，用猜测的`SEQ#`，发送一个RST攻击包
		- 若序列号在窗口内，则接收方发送一个挑战ACK包；否则，被丢弃
	- 以自己为源地址，发送100个RST攻击包
		- 若猜对，则观察到99个ACK包；否则，100个
- 攻击步骤3：推测`ACK#`，与步骤1原理类似，但发送的是DATA包
	1. 以发送方为源地址，用猜测的`ACK#`，发送一个DATA攻击包
		- 若`ACK#`在挑战窗口内，则接收方发送一个挑战ACK包；否则，被丢弃
	- 以自己为源地址，发送100个DATA攻击包
		- 若猜对，则观察到99个ACK包；否则，100个
- 攻击效果与优化：
	- 蛮力：10^4(`SPORT`) x 10^9(`SEQ#`) x 10^9(`ACK#`) = 10^22
	- 新攻击：10^4(`SPORT`) + 10^9(`SEQ#`) + 10^9(`ACK#`) = 10^9
	- 中断攻击SSH：耗时~42秒，成功率96%
	- 劫持攻击Tor：耗时~61秒，成功率89%
	- 劫持攻击Web：耗时~81秒，仿冒成功率70%

- 防御方案：随机，特别大，移除全局C-ACK速率限制（2016年7月Linux内核4.7上补丁）
		
###2. 路由安全

####源路由（source routing）攻击：

- IP loose source and record route (LSRR) 选项（参考[RFC1812:   Requirements for IP Version 4 Routers](https://tools.ietf.org/html/rfc1812)）可指定包经过路径/返回路径
	- 源地址始终为最初发包者，目的地址在每一跳都更新为LSRR选项中下一地址
	- 最终接收者用LSRR选项以源路径的逆序来应答

- 攻击者A冒充节点V（源地址欺骗），令目的IP地址为T的数据包经过A
- T上的防火墙或应用以为是V来访问，T以A为中间节点将应答包发送给V

```                 src  dst  LSRR             
                     |    |     | 
                from V to T via A
 Attacker (A)   —————————————————>   Target (T)  
       ^                                 |
       |        from T to V via A        |
       +—————————————————————————————————+ 
```
- 防御：禁止LSRR


####其他路由相关攻击

- [RIP协议](https://en.wikipedia.org/wiki/Routing_Information_Protocol)中伪造路由消息
- [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)重定向攻击，目标不可达，TTL超时等等
- [BGP安全](bgp-sec.pptx)后面课程会学习

###3. “认证”服务器

一种替代基于地址的认证的方法是使用“认证服务器”。该认证服务器为客户提供认证服务，与其他服务器进行认证。显然，通过其他机器来实现认证不是好主意！

###4. 龙出没

- [finger协议](https://en.wikipedia.org/wiki/Finger_protocol)所提供的用户信息，例如姓名、电话号码，可能被口令破解器所利用
- 电子邮件中发件人地址缺乏认证，邮件内容缺乏保护
	- 旧的[POP](https://en.wikipedia.org/wiki/Post_Office_Protocol)中，用户名和口令在一条命令中，容易被窃听或泄露
	- 现在推荐使用[IMAP](https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol)-over-SSL，PGP
- FTP认证，匿名FTP
- SNMP认证
- 远程启动认证：RARP+TFTP，BOOTP+TFTP，DHCP
- [DNS安全](dns-sec.pptx)后面课程会学习

###5. 简单攻击

- 局域网内：窃听，ARP欺骗，广播风波（1个ICMP echo触发N个reply）
- TFTP无认证
- 特权端口只能被分配给特权进程，但以此作为认证机制的一部分并不安全

###6. 全面防御

- 认证：密码学与TCP/IP结合
- 加密：链路级加密，TCP
- [可信系统（Trusted System）](https://en.wikipedia.org/wiki/Trusted_system)：用于实现特定安全策略的系统

###7. 结论与反思

- 1989年互联网简单的多，友好的多。今天的关键问题不是认证（authentication），而是授权（authorization）:如何知道某一方是否允许行使某一行为？
- 多数安全问题源于有bug的代码
- 攻击通常需要一些辅助数据。只能创建一个TCP连接的攻击者不能猜测正确的序列号







