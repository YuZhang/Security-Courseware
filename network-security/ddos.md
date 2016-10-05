#DDoS（分布式拒绝服务攻击）

###哈尔滨工业大学 网络与信息安全 张宇 2016

---

著名DDoS攻击：[Qsmind DDoS攻击年鉴](http://www.qsmind.com/index.html)

- 1999年8月17日，[Trinoo](https://en.wikipedia.org/wiki/Trinoo)网络针对[明尼苏达大学校园网发动第一次真正的DDoS攻击](http://www.cert.org/historical/incident_notes/IN-99-04.cfm)
- 2000年2月，Yahoo!, eBay和Amazon遭受DDoS攻击，攻击者为[MafiaBoy](https://en.wikipedia.org/wiki/MafiaBoy)
- 2002年10月，13个根服务中9个遭受DDoS攻击，攻击者为[MafiaBoy](https://en.wikipedia.org/wiki/MafiaBoy)
- 2010年12月，“复仇阿桑奇行动”（Operation Avenge Assange），[Aonymous](https://en.wikipedia.org/wiki/Anonymous_(group))针对关闭维基解密捐助支付的PayPal和其他金融服务公司发动了DDoS攻击，属于[“报复行动”](https://en.wikipedia.org/wiki/Operation_Payback)的一部分
- 2013年3月，欧洲反垃圾邮件组织Spamhaus对BBC宣称[“正遭受300G+的DDoS攻击”](https://www.spamhaus.org/news/article/695/answers-about-recent-ddos-attack-on-spamhaus)，攻击手段是[僵尸网络和DNS反射攻击](https://blog.cloudflare.com/the-ddos-that-knocked-spamhaus-offline-and-ho/)
- 2014年2月，[CloudFlare客户遭受400G的NTP Flood攻击](https://blog.cloudflare.com/technical-details-behind-a-400gbps-ntp-amplification-ddos-attack/)
- 2015年3月末，GitHub上反审查工具遭受最大规模DDoS攻击，[相关报道](http://arstechnica.com/security/2015/03/github-battles-largest-ddos-in-sites-history-targeted-at-anti-censorship-tools/)，[攻击时GitHub状态页](https://status.github.com/messages/2015-03-30)
- 2016年9月中旬，超过14.5万被劫持摄像头发动了1.1Tbps的DDoS攻击，成为[史上最大规模DDoS](http://arstechnica.com/security/2016/09/botnet-of-145k-cameras-reportedly-deliver-internets-biggest-ddos-ever/)

US-CERT定义的DoS攻击症状：网络性能恶化、特定网站不可用、不能访问任意网站、垃圾邮件数量激增、网络连接中断、长期决绝访问或任何互联网服务

发动DoS攻击比许多其他攻击的代价要高；防御DoS不是阻止所有攻击，而是提高攻击的门槛； 或许一种最根本的解决方法是令攻击者对目标没兴趣

参考资料：[RFC4732: Internet Denial-of-Service Considerations (2006)](https://tools.ietf.org/html/rfc4732)

##攻击类型 

###攻击链路

- 直接发送大量流量令链路拥塞，导致关键服务或路由故障

###攻击末端系统

- 利用软件漏洞，例如[Ping of death](https://en.wikipedia.org/wiki/Ping_of_death)攻击发送大于65535字节的ping包（ICMP echo request），导致接收方在处理数据包（组装IP分片）时缓冲区溢出
- 耗尽应用资源：单个应用程序的内存，CPU，磁盘，进程/线程数，最大连接数被耗尽
	- 例如一个FTP服务器的最大同时连接数（10年以前还需要从FTP下载电影，校内的FTP都有连接数限制）
	- [Fork bomb](https://en.wikipedia.org/wiki/Fork_bomb)：也叫“Wabbit”，自复制程序；例如，在Bash中执行 “`:(){ :|:& };:`”
- 耗尽操作系统资源：
	- TCP SYN flood引起服务器生成很多半开连接，占用所有系统可用连接
	- 基于中断的内核处理大流量时导致“活锁”，CPU都用来处理包接收中断，而不是处理收到的包
	- [Slowloris（懒猴）](https://en.wikipedia.org/wiki/Slowloris_(computer_security))：HTTP GET时只发送部分请求，缓慢更新，永不关闭
	- HTTP SlowPOST：也称为[R-U-Dead-Yet (RUDY)](https://sourceforge.net/projects/r-u-dead-yet/)，Post时以极慢速度（1byte/110s）来发送消息
	- [ReDoS](https://en.wikipedia.org/wiki/ReDoS)：利用指数复杂性的正则表达式消耗计算资源，可用来攻击IDS等，例如对于正则表达式“`^(a+)+$`”，输入`aaaaaaaaaaaaaaaaX`有65536个可能路径
- 触发锁死与限额耗尽：
	- 用户认证机制在多次尝试失败后会锁死账号
	- 租用Web服务有时有流量限额，耗尽后服务会被关闭
- DDoS攻击工具：
	- [Trinoo](https://en.wikipedia.org/wiki/Trinoo)：主从式DDoS攻击程序集 
	- [Tribe Flood Network](https://en.wikipedia.org/wiki/Tribe_Flood_Network)：实施ICMP/SYN/UDP flood等多种攻击的程序集
	- [LOIC低轨道粒子炮](https://en.wikipedia.org/wiki/Low_Orbit_Ion_Cannon)：开源工具被用于匿名者的“报复行动”
	- [HOIC高轨道粒子炮](https://en.wikipedia.org/wiki/High_Orbit_Ion_Cannon)：2012年开发以取代LOIC，匿名者用其攻击美国司法部

[一种针对TCP的低速率DoS攻击](http://www.cs.northwestern.edu/~akuzma/doc/ShrewToN.pdf)：Shrew（鼩鼱，qu2jing1，一种像老鼠的有毒小动物）


###攻击路由器

[何为'数字大炮'？](http://blog.hit.edu.cn/yuzhang/post/4.html)

‘数字大炮’的说法，最初来自新华网的一篇新闻[“美发明网络“数字大炮”可摧毁整个互联网“](http://news.xinhuanet.com/mil/2011-02/15/c_121082249.htm)。该新闻翻译自一个科普杂志NewScientist上对NDSS'2011会议上一篇文章的报道[“The cyberweapon that could take down the internet（能够摧毁Internet的数字武器）”](http://www.newscientist.com/article/dn20113-the-cyberweapon-that-could-take-down-the-internet/)。标题中的‘cyberweapon’加上报道中出现了‘digital ordnance’的文字，可能是新华网翻译为‘数字大炮’原因。不过，‘cyberweapon’（数字/网络武器）泛指军用网络攻击技术的说法更为普遍，‘digital ordnance’只是作者的一个比喻。

NDSS'2011会议上的文章为[“Losing Control of the Internet: Using the Data Plane to Attack the Control Plane（Internet失控：利用数据面攻击控制面）”](http://www-users.cs.umn.edu/~hopper/lci-ndss.pdf)。该文章主要是对NDSS'2007上一片文章[“Low-Rate TCP-Targeted DoS Attack Disrupts Internet Routing（针对TCP的低速DoS攻击干扰Internet路由）”](http://www.isoc.org/isoc/conferences/ndss/07/papers/low-rate_TCP-targeted_DOS_attacks.pdf)所提出的方法进行模拟评价。这两篇文章中也都没有‘cyberweapon’或‘digital ordnance’的说法。因此，严格的说，并不存在所谓的‘数字大炮’技术。 

NDSS'2007上的文章提出，利用针对TCP的低速DoS攻击，使得一对BGP路由器间基于TCP的会话因拥塞而中断；目标BGP路由器会撤销已有路由，并寻找替代路由；当新路由建立后，攻击流量流向新路径，旧连接上拥塞消失，旧的BGP会话恢复；此时，攻击流量再次被路由到目标连接上，拥塞又发生，会话再次中断；上述情况周而复始，导致路由摆动，严重影响网络连通性。不仅如此，因为在BGP中，局部变化会传播到整个网络，具有一种‘放大器效应’，所以整个网络上路由器都会不同程度受到影响。该攻击的特点是，通过数据面上的攻击引起控制面上的故障。因此，理论上对路由协议的改进无法彻底阻止该攻击，而根本的解决方法是，分离数据面流量和控制面流量，以保证BGP会话流量不受干扰。

另外，针对TCP的低速DoS攻击最初是在SIGCOMM'2003会议上提出的，论文[“Low-Rate TCP-Targeted Denial of Service Attacks（针对TCP的低速DoS攻击）”[期刊版]](http://www.cs.northwestern.edu/~akuzma/doc/ShrewToN.pdf)。该攻击通过测量目标主机TCP行为参数，有针对性的发出特定时间间隔的脉冲流量，从而引起TCP连接中断。该攻击的主要优点是所需攻击流量规模较小，无需持续阻塞目标链路；缺点是需要提前获得目标主机TCP参数。

综上，‘数字大炮’是媒体的一种渲染，其原理是通过DoS攻击来打断BGP会话，引发路由摆动。

###攻击进行中的通信

例如在前面学习的TCP重置和劫持攻击

###利用受害者本身的资源攻击

一个例子是利用[UDP echo](https://en.wikipedia.org/wiki/Echo_Protocol)和[UDP chargen](https://en.wikipedia.org/wiki/Character_Generator_Protocol)服务器：

- UDP Echo（端口7）：以与请求相同的包做应答
- UDP Chargen（端口19）：丢弃请求，应答一个预设字符串

攻击者将源地址伪造为chargen服务器地址，向受害者echo端口发送一个包，echo应答又触发chargen服务器发送一个包，导致两台机器“打乒乓球”。

###攻击本地主机或设施

- 耗尽DHCP服务中地址池，伪造DHCP应答
- ARP伪造；伪造ARP应答；伪造MAC地址
- 广播风暴：向广播MAC地址发包
- 802.11无线网络
	- 在非特许频段上采用CSMA/CA方式，会发生信源干扰，易于被无线电拥塞攻击
	- 链路自动配置中漏洞，伪造Beacon帧，伪造/干扰认证/解认证（authentication）、连接/解连接(assocaition)等

###通过DNS攻击站点

- 直接攻击权威服务器，攻击根服务器
- 之前学习的DNS缓存下毒

###攻击防火墙/IDS

- 防火墙/IDS分为有状态和无状态两类，防火墙故障通常引起断网
	- 对于有状态，可通过构造病态流量令内存过载
	- 对于无状态，可简单以大流量来耗尽处理资源
- 对于反应型IDS，以受害者身份伪造攻击流量，令IDS封堵受害者

###物理DoS
- 2015年5月27日支付宝故障是由于杭州市萧山区某地光纤被挖断

###垃圾邮件与黑洞列表

- 大量垃圾邮件是对邮件系统的DoS
- 黑洞列表包括发送垃圾邮件的拨号ISP和邮件服务器IP地址。攻击者伪装为受害者发送垃圾邮件，令未发送垃圾邮件的受害者加入黑洞列表中
	- 例如我们实验室的pact518邮箱多次被gmail封堵


##攻击放大器

###攻击

- smurf攻击：伪造受害者源地址+ICMP echo request发送到子网广播地址
- DNS放大：伪造受害者源地址发送查询+应答包远大于查询包
- TCP放大（“bang.c”）：伪造受害者源地址发送SYN包+服务器重传多个SYN|ACK包
- 在协议负载中包含IP地址或主机名，例如SIP中SDP
- UDP放大比例
	- NTP - 556.9
	- CharGen - 358.8
	- DNS - 179
	- [QOTD (The Quote Of The Day)](https://en.wikipedia.org/wiki/QOTD) - 140.3
	- [Quake Network Protocol](http://blog.alejandronolla.com/2013/06/24/amplification-ddos-attack-with-quake3-servers-an-analysis-1-slash-2/)- 63.9
	- BitTorrent - 54.3

###防御
- 入口过滤来阻止源地址伪造
- 避免远大于请求包大小的应答包大小，除非有握手来验证源地址
- 初始连接建立过程中，应由客户端负责重传
- 避免触发第三方连接，除非之前有验证

##DoS缓解策略

原则上不可能区分一个足够精妙的DoS攻击和一伙蜂拥而至的用户，出乎意料的大量但非恶意的流量和DoS攻击有一样的效果

- 避免优于普通资源消耗的攻击
- 最小化普通资源消耗攻击对真正用户排挤程度

尽快检测，尽可能从源头阻止

- 分类：
 	- 防御位置：源，目的，网络，混合
 	- 防御时间：事前（攻击阻止），事中（攻击检测），事后（攻击溯源与响应）


###协议设计

- 不要保留未验证主机的状态

	- [SYN cookies](http://cr.yp.to/syncookies.html): 在三次握手过程中，服务器不保留客户端SYN包或会话信息，而是在SYN|ACK包的ISN中嵌入连接信息（cookie），之后用客户端返回包ACK号来验证

		- 服务器ISN构造：
			- 前5位: `t mod 32`, `t`计时器每64秒加1
			- 中3位: `m` = MSS(Maximum Segment Size)编码
			- 末24位: `s` = MAC(TCP4元组，`t`，密钥)
		- 验证返回ACK：
			- 与当前时间比较，检查`t`是否超时
			- 重新计算`s`验证cookie
			- 解码`m`值
		- 问题：这对TCP劫持有什么影响？

- [RFC4987: TCP SYN Flooding Attacks and Common Mitigations (2007)](https://tools.ietf.org/html/rfc4987)

- 增加伪装真正用户的难度
	- Puzzle：强制攻击者进行一些计算
	- 反向图灵测试：对人容易但对机器难的Puzzle
		- 例如，验证码，Completely Automated Public Turing test to tell Computers and Humans Apart (CAPTCHA)）
	- 可达性测试：强制客户端证明其从指定IP地址接收流量
	- 问题：增加真正用户负担，对以真正用户行为的攻击无效
- 优雅路由退化（Graceful Routing Degradation）
	- 优雅退化，即容错。
	- 发生故障后，RIP将度量设为无穷，回复后收到新更新
	- BGP是有状态的（累积更新），恢复需完全重启整个会话，重传路由表
- 自动配置与认证
	- 未认证的自动配置便于部署，但易于被攻击

###网络设计与配置

- 网络在面对带内（数据面或控制面）DoS攻击时，应提供私有带外访问（通过一个不同的基础设施）

- 冗余与分布式服务：这是基本的容错设计原则
- 路由邻接性认证：相邻路由器间通过密码学认证
- 隔离路由器到路由器流量：即分离控制面与数据面流量

###路由器实现问题

- 检查协议词法与语义：
	- 谁发送消息？是否遵循协议格式？发送时间是否正确？
- 一致性检查：
	- 例如BGP中，对于一个前缀，来自多个邻居AS的起源是否一致
- 通过操作调整来增强路由器鲁棒性：
	- 例如调整BGP的KeppAlive和Hold Timer值来最小化BGP互联会话重置
- 恰当处理路由器资源消耗：一个例子，
	- 高端路由器中由ASCI来处理大部分流量，一些异常包由通用CPU处理
	- 存在一种低PPS攻击，来饱和ASCI和CPU之间的队列
	- 对策是采用多个此类队列，并令攻击者难以填满多个队列

###末端系统实现问题

- 状态查询复杂性：
	- 避免活锁：用poll替代中断，例如[Linux New API (NAPI)](https://en.wikipedia.org/wiki/New_API)
	- 会话ID使用不可预测值：例如TCP的ISN，DNS的源端口号和ID
- 操作问题：
	- 尽早清除坏流量：例如运营商实现入口过滤
	- 建立监测框架：运营商建立监测框架来检测异常网络活动

###应急响应

[IP traceback](https://en.wikipedia.org/wiki/IP_traceback)：追踪一个IP包的起源

- 概率性包标记
- 确定性包标记
- 




