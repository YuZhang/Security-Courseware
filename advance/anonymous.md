#  匿名通信

### 哈尔滨工业大学 网络与信息安全 张宇 2018

---

## 1. 背景简介

- 人天生想隐藏自己；没人看见自己，会感觉安全？
	- 不同政见者、自由出版商、私密聊天、执法者、罪犯、任何人 
	- 你：给谁发消息、正在上哪个网站、在哪里上网、你买了什么、你再吃什么...
	- 政府/军队：隐藏在公网上的情报收集，隐藏专用网络，国际协作
- 匿名定义：
	-  不可关联性(Unlinkability): 观察者不能将某个个体和其消息、行为或身份标识符等关联起来
	-  匿名(Anonymity)：观察者不能充分地从一群主体的集合中识别出某个个体
	 	-  接收者匿名，发送者匿名：观察者不能将消息与其接收者或发送者关联起来
		-  关系匿名：观察者不能将某个通信的双方关联起来
	-  不可观察性(Unobservability): 观察者不能充分辨别其任何感兴趣的东西(如个体、消息、行为等）是否存在
- 匿名需要伙伴
	- 全世界只有两个人，何谈匿名？ 
	- 自己不能匿名自己
	- 匿名意味着隐藏在一群人之中
	- 我为人人，人人为我
	- 匿名网络需要分散性、多样性
- 网络是开放的、公开的
	- 互联网是一个开放网络
	- IP地址标识通信端点
	- 网络运营商、情报机关、工作单位监控流量
	- Wifi接入点，DNS递归服务器、网站/应用追踪
- 去匿名：
	- 被动流量分析：通过分析网络流量来识别个体；因此需要其他人承载流量
	- 主动流量分析：注入攻击流量来帮助识别个体；因此需要抹掉流量特征
	- 攻破网络节点：直接控制中继点；因此不能信任特定路由器

## 2. Crowds

[Crowds](https://en.wikipedia.org/wiki/Crowds): 一种用于匿名Web浏览的匿名网络。核心思想是将一个用户与一群用户相混合，在一组相似用户之间来随机路由每个用户的通信。组成员和接收者都不清楚报文来自于哪里。

[论文： Michael Reiter and Aviel Rubin (June 1998). "Crowds: Anonymity for Web Transactions" (PDF). ACM Transactions on Information and System Security.](http://avirubin.com/crowds.pdf)

### 2.1 工作原理

1. 加入一个由blender管理的crowd：
	- 一个新用户在一个blender服务器上注册，从而和同一个blender上注册的其他用户加入同一个crowd。
	- 用户主机上的web代理程序，称为jondo（“John Doe”），负责转发应用层请求，因此消息中不含IP/TCP头部，包含目的信息。
	- blender和jondo之间共享口令，用来加密两者之间报文。
	- blender为每对jondo产生一组密钥，用于jondo之间保密通信。
2. 用户通过浏览器对Web服务的请求被转发给本地jondo，jondo剥离与发送者有关的信息，例如cookie，而只转发应用层请求。
3. 当jondo接收到来自本地浏览器或其他jondo的一个请求消息时
	- 记录请求的来源为前继节点，采用以下方式转发：
		- 以概率p>1/2，将请求解密后加密转发给crowd中随机挑选的节点（包括自己）jondo；
		- 以概率1-p，将请求解密并以明文转发给最终目的；
	- 由此形成一条从发送者到目标的随机路径；后续一段时间内来自同一初始jondo的请求都会经过该路径。每隔一段时间路径会重构。
4. 当收到来自web服务器的应答消息时，将应答转发给前继节点，即应答会沿着反向路径到达最初发出请求的jondo，并返回给浏览器。

```
       <---          <---          <--- ....<--+
sender ---> jondo-13 ---> jondo-65 ---> ... +  |
jondo                                       |  |
                                            |  |
              web server <--- jondo-20 <----+  |
                         --->          --------+
```


### 2.2 攻击类型与安全性分析

*Crowds不提供在全局攻击者下的发送者-接受者不可连接匿名性。* 
*Crowds中相邻节点间采用对称加密，每个节点都可以窃听消息。*

匿名程度：

- absolute privacy: 攻击者无法感知通信的存在
- beyound suspicion: 是发送者概率～1/n (n=crowd规模)
- probable innocence: 是发送者概率<=1/2
- exposed: 知道谁是发送者
- provably exposed: 能够证明谁是发送者

攻击者类型与匿名性：

- 本地窃听者：攻击者可以窃听到用户主机往来的通信。
	- 发送者：exposed（没有收到消息，但发出消息）
	- 接收者：beyound suspicion（由于通信被加密，除非直接发送给目的）
- 目的web服务器：
	- 发送者：beyound suspicion
	- 接收者：N/A
- 成员合谋：crowd内其他c个成员共享信息，甚至偏离协议
	- 发送者：probable innocence (若n足够大，absolute privacy)
	- 接收者：absolute privacy（若n足够大）

#### 在成员合谋情况下，发送者匿名是probable innocence的证明。

定义以下事件：

```
- 节点S：发送者。
- 节点A：在随机路径中最前面的攻击者A。
- 事件H_k：A在随机路径上的第k跳。第0跳是S。
- 事件H_k+： H_k V H_(k+1) ... 
- 事件H：H_1+，A在路径上。
- 事件I：S是A的前继节点。
```

合谋攻击者们去匿名化的唯一策略是*将接收到第一个消息的来源当作发送者*。当A在随机路径上（事件H发生），并且S是A的前继（事件I发生）时，这种去匿名策略发现的发送者是真正的发送者。由此，给出匿名性probable innocence定义：当A在路径上，S是A的前继的概率小于1/2。

```
- 定义：S是probable innocence，若P[I|H]<=1/2。
- 定理：`若n >= p/(p-1/2)*(c+1)，则P[I|H]<=1/2。`
```

证明：

```
- P[H_i] = (p(n-c)/n)^(i-1) * (c/n)。前i-1跳不是攻击节点，第i跳是。
- P[H] = c / [ n - p(n-c) ]。
- P[I] = P[H_1]P[I|H_1] + P[H_2+]P[I|H_2+] = ...略
- P[I|H] = P[I and H] / P[H] = P[I] / P[H] (由于I => H)
- = [n - p(n-c-1)] / n <= 1/2
- 得到 n >= p/(p-1/2)*(c+1)
```

当p=3/4，n>= 3(c+1)。当n足够大，则去匿名化概率足够小。

## 3. Mix

[Mix networks](https://en.wikipedia.org/wiki/Mix_network): 一种由mix代理服务器互联而成的匿名网络。发送者事先确定路径，并用“俄罗斯套娃”的方式将消息用路径上mix的公钥层层加密，每个mix接收到消息后解密剥去一层，直到路径最后一跳解密消息并转发给目的。

论文：[David Chaum, Untraceable electronic mail, return addresses, and digital pseudonyms, Comm. ACM, 24, 2 (Feb. 1981); 84-90.](http://www.cs.utexas.edu/~shmat/courses/cs395t_fall04/chaum81.pdf)

注：原始论文发表时，现代密码学研究刚刚开始。因此，其中密码学部分描述在今天看来需要修改。例如，非确定加密如今已是默认的，不需要显式地说明需添加随机量。另外，将随机量作为对称密钥也不合适。

发送者S通过Mix服务器M向接收者R发送一个消息p：

```
E_x(y): encrypt y with key x.

S                            M                            R
p                            |                            |
| ----- E_M( E_R(p), R) ---->|                            |
|                        E_R(p), R                        | 
|                            | --------- E_R(p) --------> |
|                            |                            p
```

R作出应答q，但对R隐藏S的身份，即保持发送者匿名性：

```
E_x(y): encrypt y with key x.

S                                         M                            R
| generate a shared key k.                |                            |
| ----- E_M( E_R(p, E_M(S), k), R ) ----> |                            |
|                              E_R(p, E_M(S), k), R                    |
|                                         |--- E_R(p, E_M(S), k) ----> |
|                                         |                       p, E_M(S), k
|                                         |                         response q
|                                         |<--- E_M(S), E_k(q) ------- |
|                                      S, E_k(q)                       |
| <----- E_k(q) --------------------------|                            |
q
```

针对发送者-接收者关联匿名性的攻击，即发现谁在和谁通信。例如，下图中攻击者尝试将p1,p2,p3与q1,q2,q3相关联。

```
input at different times           output at the same time
                        +---------+
sender1 --p1----------->|         |--------q1---->receiver1
sender2 ----p2--------->|   Mix   |--------q2---->receiver2
sender3 ------p3------->|         |--------q3---->receiver3
                        +---------+
```

- 攻击1：出现时间。
	- 防御：Mix收到数据包后不立刻转发，而是等待一会儿，同时乱序发出。
- 攻击2：报文大小。
	- 防御：将数据包padding为相同大小后，再转发。
- 攻击3：发包频率。
	- 防御：固定速率，idle包
- 攻击4：Mix被入侵
	- Mix cascade：多个Mix形成固定一串，一头入，另一头出。只要其中有一个Mix安全，就能保证匿名。消息被层层加密，如下图：

```
S --- A --- B --- C --- R

+--------------------------------+
|     +-------------------------+|
|     |     +------------------+||
|     |     |     +---------- +|||
| E_A | E_B | E_C | E_R(p), R ||||
|     |     |     +-----------+|||
|     |     +------------------+||
|     +-------------------------+|
+--------------------------------+
```

## 4. Tor

### 4.1 Tor简介

[Tor](https://en.wikipedia.org/wiki/Tor_(anonymity_network)): 一种基于Mix的匿名通信系统与网络，其名字来自"The Onion Router"的缩写。Tor设计发表在2004年 USENIX Security Symposium上，论文题目[Tor: The Second-Generation Onion Router](https://svn.torproject.org/svn/projects/design-paper/tor-design.html)。[根据2008年5月统计](https://metrics.torproject.org)，Tor覆盖网中relay节点达6千，bridge节点达2千，用户近2百万。

Tor历史：

- 上世纪90年代中期由美国海军研究实验室的员工，数学家保罗·西维森（Paul Syverson）和计算机科学家迈克·里德（G. Mike Reed）和大卫·戈尔德施拉格（David Goldschlag），为保护美国情报通信而开发。1997年交由DARPA做进一步开发。
- 2002年9月20日，西维森和计算机科学家罗根·丁格伦（Roger Dingledine）和尼克·马修森（Nick Mathewson）开发出Tor的测试版并命名为“洋葱路由项目”（The Onion Routing project），简称TOR项目。
- 2004年8月13日，西维森、丁格伦和马修森于13th USENIX Security Symposium上提出了“Tor: The Second-Generation Onion Router”，即第二代洋葱路由。
- 2004年，美国海军研究实验室以自由软件许可证发布了Tor代码，电子前哨基金会开始资助丁格伦和马修森继续开发。2005年后期，电子前哨基金会不再赞助Tor项目，但他们继续维护Tor的官方网站。
- 2006年12月，丁格伦、马修森及另外五人成立了The Tor Project，一个位于马萨诸塞州的非营利组织，负责维护Tor。

Tor特点（相对于第一代洋葱路由）：

- 完美前向保密：发起节点与每个OR分别建立临时会话密钥。即使一个OR之后被攻破，不会造成之前的会话密钥泄露，也就保证过去的密文无法被解密。
- 协议与匿名化分离：支持SOCKS代理接口，支持绝大多数基于TCP协议的应用。
- 没有mixing，填充，流量整形：尚未找到低延迟解决方案。
- 多路复用：允许多个TCP数据流共用同一条虚电路。
- Leaky-pipe电路拓扑：发起点可以令流量从电路中间直接“泄漏”到目的，从而防范针对电路末端的攻击。
- 拥塞控制：去中心化的端到端拥塞控制，允许每个节点检测拥塞并向发送方发出信号停止消息传输，直到拥塞消失。
- 目录服务器（vs. 全网洪泛）：目录服务器存储了所有Tor节点的信息和状态，包括IP地址、端口号、运行的Tor服务版本、指纹、带宽、运行时间、公钥等信息。
- 可配置出口策略：出口节点（即最后一跳节点）可以选择排除某些出口（包括出口国家、IP地址、端口等），以防止出口节点被恶意滥用。
- 端到端完整性检验：Tor采用sha-1算法对消息进行hash处理，并将结果存储在报文头部（占4字节），在出口端校验数据的完整性。
- Hidden service：为保护服务器匿名性，客户端在连接隐藏服务时，需要协商汇聚点（Rendezvous points），并通过汇聚点连接隐藏服务。
- 抵御审查：当用户所处的地区屏蔽Tor节点时，用户需要借助“bridge”来连接到Tor网络。“bridge”本质上是一个特殊的入口节点，它的信息没有被存储到目录服务器中，而是只被少数人知道，因此降低了被屏蔽的概率。

### 4.2 Tor设计

推荐参考资料：

- [Tor官方文档](https://gitweb.torproject.org/torspec.git/tree/)
- [How Tor Works](https://jordan-wright.com/blog/2015/02/28/how-tor-works-part-one/) 【[中文](https://www.anquanke.com/post/id/84680)】

#### 4.2.0 基本概念

- Onion Router：洋葱路由器，也称中继Relay
	- 每个OR都维持着一个长期身份密钥。
	- 以及一个短期的洋葱密钥（建立虚电路时使用）。
	- OR之间建立TLS连接为Channel。
	- 可以作为目录缓存。
- Onion Proxy：洋葱代理，用户运行在本地的软件，也称客户端。
	- 用来帮助用户从目录服务器中获取信息，选取OR并建立虚电路，传输数据。
	- OR与OP之间建立TLS连接Channel。
- Circuit：电路，一串顺序相连的OR
	- 每个OR只知道自己的前继和后继。
	- 多条电路可复用一条OR-OR或OP-OR间Channel，多个TCP流可复用一条电路。
- 从客户端到目的服务器之间电路通常经过3个OR，分别称为guard (entry)、middle、exit node/relay。
- Bridge：未公开的OR。目前只用于guard relay。
- Directory Authority: 9台维护OR列表（彼此之间运行共识协议），1台（Tonga）维护Bridge列表。
- Rendezvous point：用于客户端和隐藏服务之间通信，两者分别通过三个中继相会在RP。
- Cell：数据传输的基本单元
	- Cell为固定大小512字节，由对称密钥加密。
	- Cell包含circID，command，data等
	- command分为两种，虚电路构建时的control cell和数据传输时的relay cell。
		- control cell由接收到的节点解释来操作电路，命令包括padding、create(d)、destroy
		- relay cell包含端到端streamID，还包含子命令data（承载数据）、begin、end、connected、sendme等流操作，以及extend(ed)、truncate(d)等电路操作。
		
```
   OP  ----- Guard(Entry) ----- Middle ----- Exit ----- destination
(client)        /Bridge
```

#### 4.2.1 构建虚电路

Tor构建虚电路时，采用逐跳扩展的方式，即用户先与OR1建立连接，然后用户再通过OR1与OR2建立连接...以此类推。建立虚电路时，使用Diffie–Hellman+RSA的加密方式协商会话密钥。传输数据时，使用128-bit AES CTR进行数据加密。

```
 Alice                                OR1                              OR2    
   |---------Create c1,E(g^x1)-------->|                                |                        
   |<-------Created c1,g^y1,H(K1)------|                                |        Legend:         
   |                                   |                                |  E(x)--RSA encryption  
   |---Relay c1 {Extend,OR2,E(g^x2)}-->|                                |  {x}--AES eccryption   
   |                                   |--------Create c2,E(g^x2)------>|  cN--a circID              
   |                                   |<-----Created c2,g^y2,H(K2)-----|  K1=g^x1y2                      
   |<--Relay c1 {Extended,g^y2,H(K2)}--|                                |  K2=g^x2y2                      
   |                                   |                                |                        
-----------------------------------------------------------------------------(unencrypted)  website
   |                                   |                                |                        |
   |--Relay c1 {{Begin <website>:80}}->|                                |                        |
   |                                   |-Relay c2 {Begin <website>:80}->|                        |
   |                                   |                                |<----(TCP handshake)--->|
   |                                   |<-----Relay c2 {Connected}------|                        |
   |<------Relay c1 {{Connected}}------|                                |                        |
   |                                   |                                |                        |
   |--Relay c1 {{Data,"HTTP GET..."}}->|                                |                        |
   |                                   |-Relay c2 {Data,"HTTP GET..."}->|                        |
   |                                   |                                |------"HTTP GET..."---->|
   |                                   |                                |<------(response)-------|
   |                                   |<----Relay c2{Data,(response)}--|                        |
   |<--Relay c1{{Data,(response)}}-----|                                |                        |
   |               ...                 |             ...                |          ...           |
```

现在假设Alice想要通过Tor网络中两台OR来访问一个网站。需要进行以下几个步骤：

1. Alice的OP从目录服务器中获取节点信息，并通过Tor的路由选择算法进行选路（图中选取了OR1和OR2作为中间节点进行传输）。
2. Alice先与OR1协商密钥K1，建立虚电路。
3. Alice通过OR1与OR2建立虚电路。该过程与步骤2基本相同，只是Alice与OR2进行通信时，由于需要经过OR1，因此它们之间的通信都需要使用会话密钥K1进行AES加密。在Alice与OR2协商出会话密钥K2后，整个虚电路建立完成。
4. Alice向website发送请求，将请求按照经过OR的逆序进行AES加密，每到一个OR都解密并继续传递，直到website。
5. website向Alice发出响应，与请求时的过程正好相反。每台OR都将消息加密。Alice根据经过OR的顺序逐层解密得到明文。

#### 4.2.2 目录服务器

Tor选取一小部分大型的OR作为目录服务器，来记录整个网络的拓扑和节点状态，客户端可以从目录服务器中获取网络状态和节点列表，其他的OR也可以上传自己的状态信息。

在所有目录服务器中，有几个可信的节点被叫做“directory authority（DA）”（截至目前共有9个），OR会定期向每个DA发布签名过的节点信息，再结合目录服务器所观测到的网络状态，多个DA使用投票算法进行投票，得到该节点的一致性描述，然后进行签名并存储。新加入的OR在正常工作前必须经过DA的测试，来保证节点的可用性以及状态信息的正确性。

OR描述符包括以下几个属性：

- Nickname：节点的昵称
- Address：IP地址
- OR port：提供流量转发服务的端口号
- Dir port：提供目录服务的端口号
- Average/Burst/Observed bandwidth：长期/短期/观察的带宽
- Fingerprint：节点公钥的哈希值
- Onion key：用于建立虚电路的短期节点公钥
- Signing key：用于对OR描述符签名的长期公钥
- Exit policy：节点的出口策略规则

OR状态信息：

- Relay identity：节点ID
- Descriptor identifier：节点描述符
- Exit/Fast/Guard/Stable flag：DA认为该节点适合作为出口/快速/入口/长期节点

#### 4.2.3 选路算法

- 在默认情况下，选择3个节点作为节点，分别为入口节点，中间节点和出口节点。
- 目录服务器中存储了所有节点的基本信息，在进行选路时主要根据节点的带宽大小与运行时间选路。
- Tor倾向于选择带宽大和运行时间长的节点作为路由节点。但同时为了保证负载均衡，在选择中间节点和出口节点时，Tor依据节点带宽的权重进行选择，即节点被选中的概率与其带宽大小成正比。
- 在选择入口节点时，由于其路由位置的重要性（与用户直接相连，一旦入口节点被攻破，则攻击者就能知道用户的真实身份），Tor采用了“Entry guard”机制。
	- 每个客户端根据节点带宽和稳定性（运行时间）选择一些节点作为守卫节点，在之后的一段时间内，该客户端在建立虚电路时只从守卫节点中选择一个作为入口节点。
	- 这种方法虽然不能从根本上杜绝入口节点被攻破的情况，但是对于那些选择了好的守卫节点的客户端，可以保证在接下来一段时间内通信的匿名性。
	- 即使不幸守卫节点中有被攻破的节点，也不会比不使用“Entry guard”的情况更糟糕。

#### 4.2.4 隐藏服务（hidden service）

Tor为服务器提供了名为hidden service（HS）特殊的保护机制，目的是保护服务器的IP地址以防止其泄露。
HS通过它随机选取的几个introduction point（TP）作为它的联系点，隐藏自己的IP地址并公布所有TP的IP地址。客户端想要访问HS，需要选取一个洋葱路由作为其RP，然后连接HS的其中一个TP，告知HS关于RP的信息，之后客户端与HS之间的通信通过RP来完成。具体步骤如下：

1. HS注册：
	1. (1) HS选择几个TP，并与他们之间分别建立虚电路。
	2. (2) HS建立与目录服务器的虚电路，并告知服务描述符号，包括HS的公钥和TP的信息。
	3. 然后HS可以公布它后缀为.onion的域名吸引用户访问。
2. 当客户端想访问某个HS：
	1. (3) 客户端从目录服务器获取相关的HS信息，包括TP信息。
	2. (4) 客户端选择一个RP并建立一条虚电路，并发送cookie。
	3. (5) 客户端选择其中一个TP建立虚电路，并发送相关信息包括RP信息、cookie和DH算法的前一半密钥。
	4. (5) TP收到客户端信息后，将其重新打包发送到HS。
3. HS收到客户端信息后：
	1. (6) 建立一条到RP的虚电路，并发送DH算法的后一半密钥、哈希值和cookie。
	2. (6) RP收到信息后，将客户端和HS的cookie匹配后，将DH算法的后一半密钥、哈希值和cookie重新打包发送到客户端。
	3. (7) 客户端收到HS信息后，生成会话密钥，完成握手，建立一条经过RP(作为Exit)的虚电路。

```
 OP               TP                    HS
  |               |<----1(choose)-------|
  |--5(RP,key)--->|-------------------->|
  |                                     |
  |                   DS<----2(TP)------|
  |<----3(TP)-------->|                 |
  |                                     |
  |-----4(choose)------->RP             |
  |<------6--------------|<--6(key,VC)--|
  |-------7(VC)--------->|
  
```

### 4.3	去匿名化攻击

由于Tor的目标定位是可以大规模部署的低延迟匿名网络，对效率和扩展性方面有较高的要求，而且允许任何人在Tor网络中布置自己的路由节点，这导致了Tor无法实现强匿名性，即Tor无法应对攻击者在控制大量Tor网络节点后进行的全局攻击的情况。

虚电路上的每一个节点都只知道自己的前任节点和后继节点的身份，因此入口节点可以知道发送的IP地址，出口节点可以知道接收端的IP地址。假设攻击者同时控制了入口节点和出口节点，那么他就可以通过某些被动分析或主动分析的攻击方法，通过入口节点和出口节点来关联发送端和接收端。

[论文：Erdin, Esra, C. Zachor, and M. H. Gunes. "How to Find Hidden Users: A Survey of Attacks on Anonymity Networks." IEEE Communications Surveys & Tutorials 17.4(2015):2296-2316.](http://pdfs.semanticscholar.org/021b/fdf7e4795271c5e7435d01c2b950d6e42ff5.pdf)

被动分析方法包括以下几种：

- 交叉攻击：攻击者通过持续观测并记录用户的网络行为，并进行交叉排除，最后锁定Tor用户的身份以及用户之间的通信关系。用户的网络行为可能包含多种：如用户在浏览网页时遵循的某种模式、用户上下线的时间、邮件服务等。这种攻击方式通常需要攻击者有潜在的怀疑对象的集合，并从中进行排除，最终得到结果。
- 流量模式关联：攻击者通过识别并记录入口节点和出口节点的流量特征，然后将通信双方的流量模式进行关联，最终得到消息的发送端与接收端的通信关系。流量特征一般包括：时间特征、数据包数量、数据的封包方式等。
- 网站指纹识别：访问不同网站时，产生的流量特征不同，攻击者可以根据这点建立网站的指纹数据库。当用户访问某网站时，可以在入口节点处捕获流量，并与指纹数据库进行匹配，最终得到该用户访问某网站这一事实。

主动分析方法包括以下几种：

- 伪造流量：攻击者虽然无法自己生成Tor流量，但是可以对原有流量进行改变。比如：复制某个cell、删除某个cell、插入一个cell、改变某个cell，这些方式都会导致传输出错，并将错误传播到出口节点，然后调用Tor的错误处理机制，拆除虚电路。攻击者可以通过识别错误信号进而关联同一虚电路上的入口节点和出口节点，从而发现用户间的通信关系。
- 标记攻击：攻击者可以在不改变源流量的情况下，在流量中插入某种信号，然后在出口节点处识别该信号，进而得到通信关系。例如，利用Tor的数据封包方式，通过数据包中包含cell的数量来对信号进行编码，然后在出口节点处识别。
- 拥塞攻击：攻击者通过增大某一节点的负载，然后来观测虚电路的拥塞状态，看虚电路是否受到影响，可以判断出虚电路是否经过该节点。通过这种方式可以发现整条虚电路的路径。
- DoS攻击：攻击者通过对正常节点进行DoS攻击后，使其瘫痪，减小网络规模，提高恶意节点被选为入口节点和出口节点的概率，从而更容易使攻击成功。

#### 4.3.1 Cell计数攻击

cell计数攻击 [论文：Ling, Zhen, et al. "A new cell counter based attack against tor." ACM Conference on Computer and Communications Security ACM, 2009:578-589.](http://delivery.acm.org/10.1145/1660000/1653732/p578-ling.pdf)

- 目的：关联发送者与接收者 
- 原理：当OR接收到数据流时，经过传输层的解析后，得到chunk的序列，一个chunk中可能包含一个或多个cell，每个cell经过OR的处理后，得到新的cell保存在输出缓冲区中，此时cell需要被重新打包成chunk，然后输出。因此可以通过对cell采用不同的打包方式，在流量中插入编码。
- 前提：攻击者已经控制入口节点和出口节点。

方法：本攻击可以从入口节点或出口节点处发起，下面假设从出口节点发起攻击：

- step 1：出口节点见过`cell_created`和`cell_relay_connected`之后，得知接下来是`cell_relay_data`。
- step 2：攻击者在出口节点对来自网站的`response`数据通过数据包的封装方式，插入二进制编码信号：三个cell从队列流出代表“1”，一个cell从队列流出代表“0”。
- step 3：入口节点收到2个`cell_relay_extended`和1个`cell_relay_connected`之后，得知接下来的序列都是`cell_relay_data`。
- step 4：攻击者在入口节点处识别该信号，并将消息发送者和接收者的IP地址关联起来。

```
OP --------- Entry --------- Mid --------- Exit --------- Website
                                 <------(1) connected
                                <-----(2) encode singals in cells
   <-----(3) connected-----
   <-----(4) inspect signals
```

#### 4.3.2 重放攻击

重放攻击 [论文：Pries, R., et al. "A New Replay Attack Against Anonymous Communication Networks." IEEE International Conference on Communications IEEE, 2008:1578-1582.](http://pdfs.semanticscholar.org/be1f/95a923d3c8a8b1bc3089913d4187626c2d7d.pdf)

- 目的：关联发送者与接收者
- 原理：由于Tor使用计数模式的AES加密，因此如果在通信时复制任意cell，则会导致消息的解码失败，可以在出口节点处捕获这一事件，然后通过时间关联入口节点和出口节点，进而关联消息的发送端与接收端。
- 前提：攻击者已经控制入口节点和出口节点，并有一台中央服务器CS。

方法：

- step 1：入口节点复制cell，同时记录并向CS上传源IP地址和复制时间，这里注意复制的cell不能是虚电路建立时的cell，否则会导致协议错误进而立刻拆除虚电路，这样通信双方的通信关系尚未建立，因此只能复制relay阶段的cell。
- step 2：出口节点在处理被复制的cell时会出现解码错误，此时记录并向CS上传目的IP地址和发现时间。
- step 3：使用对这两个事件进行时间关联，进而得到消息发送端和接收端的通信关系。

```
OP --------- Entry --------- Mid --------- Exit --------- Website
     ---(1) duplicate cells-->              |
                                   ---(2) report errors-->                           
```

#### 4.3.3 协议级hidden service发现

协议级hidden service发现 [论文：Ling, Zhen, et al. "Protocol-level hidden server discovery." INFOCOM, 2013 Proceedings IEEE IEEE, 2013:1043-1051.](http://cse.seu.edu.cn/PersonalPage/zhenling/publications_files/infocom2013_Protocol-level_Hidden_Server_Discovery.pdf)

- 目的：发现HS 
- 原理：HS在接收到损坏的数据包时，会根据Tor协议拆除到RP的虚电路，入口节点可以通过捕获拆除虚电路时发送的cell序列进而识别出该事件，然后在时间上进行关联，发现HS正在使用攻击者控制的节点作为入口节点，这样攻击者就能知道HS的IP地址。
- 前提：控制一些入口节点，一个客户端，一个RP，一台中央服务器CS用来记录数据。

方法：

- step 1：OP从目录服务器获取HS的介绍点信息，然后建立到介绍点的虚电路，并告知CS发现开始。
- step 2：HS建立到RP的虚电路，如果HS选取我们控制的入口节点，入口节点会收到相应的数据包序列，具有协议特性，入口节点收到该序列的数据包后向CS报告相关信息。最后RP会收到`Relay_Command_Rendezvous`。但这并不能唯一识别HS，还需要以下步骤。
- step 3：一旦OP和HS的连接建立，OP会向HS发送数据，但RP此时会操纵数据包，向HS转发一个损坏的数据包，RP同时向CS报告这一行为。
- step 4：损坏的数据包到达HS后，无法正确解密数据包，因此它会拆除虚电路并发送相应的数据包，这个数据包会穿过整条路径到达OP。入口节点在接收到该数据包时会向CS报告，RP也会检测到这一数据包并向CS报告。
- step 5：为了判断HS是否选择我们的节点作为入口节点，CS查询并比较以下三个记录的时间：RP发送损坏数据包、RP接收到拆除数据包、入口节点接收到拆除数据包。一旦发现三个记录的时间关联，就能通过入口节点获得HS的IP地址。

```
OP --------- RP --------- Entry ----- HS
              -------(3) bad cell----->
 <-----------(4) destroy--------------
```

----

