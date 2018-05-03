#  匿名通信

### 哈尔滨工业大学 网络与信息安全 张宇 2018

---

## 1. 背景简介

- 人天生想隐藏自己；没人看见自己，会感觉安全？
	- 不同政见者、自由出版商、私密聊天、执法者、罪犯、任何人 
	- 你：给谁发消息、正在上哪个网站、在哪里上网、你买了什么、你再吃什么...
	- 政府/军队：隐藏在公网上的情报收集，隐藏专用网络，国际协作
- 匿名定义：
	-  不可识别性(Unidentifiability): 观察者不能识别任何独立个体
	-  不可关联性(Unlinkability): 观察者不能将某个消息或行动与一个个体相关联
	 	-  接收者匿名，发送者、关系匿名：观察者不能识别出通信的接收者、发送者或双方
	-  不可观察性(Unobservability): 观察者不能对任何感兴趣的消息、行动、个体做出区分
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




1.	Tor简介
Tor是一个免费开源的软件，是对“第二代洋葱路由”的一种实现，目的是隐匿通信双方的身份，使用户在Internet上的活动难以追踪，从而保护用户的隐私。Tor的核心思想是David Chaum在1981年提出的Mix-net。发展至今，全球已经有约7000个节点以及超过200万用户，是目前应用最为广泛的低延迟匿名网络。

1.1 introduction
上世纪90年代中期由美国海军研究实验室的员工，数学家保罗·西维森（Paul Syverson）和计算机科学家迈克·里德（G. Mike Reed）和大卫·戈尔德施拉格（David Goldschlag），为保护美国情报通信而开发
1997年交由DARPA做进一步开发
2002年9月20日，西维森和计算机科学家罗根·丁格伦（Roger Dingledine）和尼克·马修森（Nick Mathewson）开发出Tor的测试版并命名为“洋葱路由项目”（The Onion Routing project），简称TOR项目
2004年8月13日，西维森、丁格伦和马修森于13th USENIX Security Symposium上提出了“Tor: The Second-Generation Onion Router”，即第二代洋葱路由
2004年，美国海军研究实验室以自由软件许可证发布了Tor代码，电子前哨基金会开始资助丁格伦和马修森继续开发
2005年后期，电子前哨基金会不再赞助Tor项目，但他们继续维护Tor的官方网站
2006年12月，丁格伦、马修森及另外五人成立了The Tor Project，一个位于马萨诸塞州的非营利组织，负责维护Tor

1.2	Mix-net（Chaum, David. Untraceable Electronic Mail, Return Addresses and Digital Pseudonyms. ACM, 1981.）
Mix-net是对基于单代理技术的匿名系统的增强，Mix系统由用户节点和提供转发服务的多个Mix节点组成。每个报文经过一组Mix节点的处理后最终到达接收者。为了消除输入报文与输出报文之间的关联性，每个Mix节点接收一定数量的报文作为输入，对这些报文进行变换并随机排序后，将报文成批输出。发送者采用转发路径上依次经过的各个Mix节点的公钥对报文进行嵌套加密处理。报文每经过一个Mix节点，该节点将自己的那一层解密，得到下一跳的地址和有效载荷，再转发给下一个节点。通过层层解密，消息最终提交给接收者。
Mix网络在传输消息时，节点之间采用公钥加密，外部攻击者以及Mix路径上除最后一个Mix节点都无法知道最终的接收者的地址。除了第1个Mix节点，其它节点都不知道发送者的身份。对于由n个Mix节点组成的转发路径，即使路径上出现n-1个合谋成员，Mix网络也能实现通信关系匿名度。
K()表示使用公钥K加密，R表示随机的字符串，A表示接收者IP地址，M表示有效载荷。
假设发送者发送信息M到A，途中经过1个mix节点。
在报文经过mix节点时，节点使用自己的私钥解密报文，得到余下的密文Ka(R0,M)以及接收者IP地址A，然后丢弃随机字符串R1，如下图所示
 

1.3	特点
Tor具备如下几个特点：
	覆盖网络：建立在TLS连接之上，每个节点都与最近通信过的节点保持TLS连接
	完美前向保密：用来产生会话密钥的长期密钥泄露出去，不会造成之前通信时使用的会话密钥泄露，即保证过去的信息无法被解密。
	使用SOCKS代理：这意味着Tor支持绝大多数基于TCP协议的程序
	多路复用：基于效率和匿名性上的考虑，Tor允许多个TCP数据流共用同一条虚电路
	拥塞控制：Tor提供了拥塞控制机制，允许每个节点检测拥塞并向发送方发出信号停止消息传输，直到拥塞消失
	目录服务器：Tor的目录服务器存储了所有Tor节点的信息和状态，包括IP地址、端口号、运行的Tor服务版本、指纹、带宽、运行时间、公钥等信息，用户在使用Tor时需要率先从目录服务器中获取节点信息
	可配置的出口策略：当节点作为出口节点时（即最后一跳节点），可以选择排除某些出口（包括出口国家、地址、端口等），这样做的好处是可以防止节点被滥用的情况
	端到端的完整性检验：Tor采用sha-1算法对消息进行hash处理，并将结果存储在报文头部（占4字节），在出口端校验数据的完整性
	Hidden service：Tor为保护服务器匿名性提供了一套特殊的保护机制。客户端在连接隐藏服务时，需要协商汇聚点，并通过汇聚点连接隐藏服务
	抵御审查：当用户所处的地区屏蔽Tor节点时，用户需要借助“bridge”来连接到Tor网络。“bridge”本质上是一个特殊的入口节点，它的信息没有被存储到目录服务器中，而是只被少数人知道，因此降低了被屏蔽的概率

2.	Tor design（Dingledine, Roger, N. Mathewson, and P. Syverson. "Tor: the second-generation onion router." Journal of the Franklin Institute 239.2(2012):135-139.）
2.1 基本概念
OR：洋葱路由，用于数据传输的节点，每个洋葱节点都维持着一个长期身份密钥（用于对节点信息进行签名）以及一个短期的洋葱密钥（建立虚电路时使用的私钥），短期的洋葱密钥需要周期性的改变来防止密钥泄露
OP：洋葱代理，通常是用户运行在本地的软件，用来帮助用户从目录服务器中获取信息，选取路由节点并建立虚电路，然后处理数据的传输
Cell：Tor中数据传输的基本单元，每个cell为固定大小512字节，由头部信息和有效载荷组成。Cell分为两种，虚电路构建时的cell和数据传输时的cell，其结构如下图。
 
create cell命令：
create/created：建立虚电路（请求）
create_fast/created_fast：快速建立虚电路，即在不使用公钥加密的情况下建立虚电路
padding：用于keepalive检测
destroy：拆除虚电路

relay cell命令：
relay data：传输数据流
relay begin：开启一个数据流
relay connected：告知OP数据流成功开启，relay begin的响应
relay end：关闭一个数据流
relay begin dir：开启一个到目录服务器的数据流
relay teardown：关闭一个损坏的数据路
relay extend/relay extended：扩展一跳虚电路
relay truncate/relay truncated：拆除部分虚电路
relay sendme：用于拥塞控制
relay resolve/ relay resolved：用于匿名DNS解析

2.2 实现方法
 
Tor构建虚电路时，采用逐跳扩展的方式，即用户先与OR1建立连接，然后用户再通过OR1与OR2建立连接……以此类推。建立虚电路时，使用Diffie–Hellman+RSA的加密方式协商会话密钥。传输数据时，使用128-bit AES CTR进行数据加密。
现在假设Alice想要通过Tor网络访问一个网站。需要进行以下几个步骤：
1. Alice的OP从目录服务器中获取节点信息，并通过Tor的路由选择算法进行选路（图中选取了OR1和OR2作为中间节点进行传输）。
2. Alice先与OR1建立虚电路。首先，Alice选取随机数x1并计算出g^x1（g为一个有限循环群的生成元），将结果使用OR1的公钥加密后，得到E（g^x1）并传输到OR1，OR1收到后使用自己的私钥对消息进行解密，得到g^x1。然后，OR1也选取随机数y1并计算出g^y1以及会话密钥K1=g^x1y1，并将g^y1和H（K1）传输到Alice。这样Alice收到后，也能计算出相同的会话密钥K1=g^x1y1，并根据H（K1）校验会话密钥的正确性。至此，Alice与OR1的虚电路建立完成。
3.Alice通过OR1与OR2建立虚电路。该过程与步骤2基本相同，只是Alice与OR2进行通信时，由于需要经过OR1，因此它们之间的通信都需要使用会话密钥K1进行AES加密。在Alice与OR2协商出会话密钥后，整个虚电路建立完成。
4.Alice向website发送请求，假设Alice要传输数据为request，将request按照路由的顺序进行AES加密，首先使用K2进行加密，再使用K1进行加密，则加密后的数据为{{request}K2}K1。然后将数据传输到OR1，OR1使用会话密钥K1进行解密后，得到{request}K2，再将数据传输到OR2，OR2使用会话密钥K2进行解密后，得到request，再将数据传输到website。（数据从OR2传输到website，虽然看似是明文传输，但实际上也进行了TLS加密）
5.website向Alice发出响应，与请求时的过程正好相反。假设数据为response，传输到OR2，OR2使用会话密钥K2进行加密，得到{response}K2，再将数据传输到OR1，OR1使用会话密钥K1进行加密，得到{{response}K2}K1，传输到Alice。Alice根据路由的顺序，先使用K1进行解密，再使用K2进行解密，最后得到明文response。

2.3 目录服务器
Tor选取一小部分大型的OR作为目录服务器，来记录整个网络的拓扑和节点状态，客户端可以从目录服务器中获取网络状态和节点列表，其他的OR也可以上传自己的状态信息。
在所有目录服务器中，有几个可信的节点被叫做“directory authority”（截至目前共有9个），OR会定期向每个directory authority发布签名过的节点信息，再结合目录服务器所观测到的网络状态，多个directory authority使用投票算法进行投票，得到该节点的一致性描述，然后使用directory authority的私钥进行签名并存储。新加入Tor网络的OR在正常工作前必须经过directory authority的测试，来保证节点的可用性以及状态信息的正确性。
OR描述符包括以下几个属性：
Nickname：节点的昵称
Address：IP地址
OR port：提供流量转发服务的端口号
Dir port：提供目录服务的端口号
Average bandwidth：节点能够长期维持的带宽
Burst bandwidth：节点在短时间内能达到的带宽
Observed bandwidth：目录服务器观测到的节点带宽
Platform：运行的Tor版本
Published：描述符生成的时间
Fingerprint：节点公钥的哈希值
Uptime：节点运行的时间
Onion key：用于建立虚电路的短期节点公钥
Signing key：用于签名的长期公钥
Exit policy：节点的出口策略规则
Contact：OR所有者联系方式
Family：相同所有者下的其他节点

OR状态信息：
Relay identity：节点ID
Descriptor identifier：节点描述符
Exit flag：directory authority认为该节点适合作为出口节点
Fast flag：directory authority认为该节点适合用于快速建立虚电路，通常是带宽大的节点
Guard flag：directory authority认为该节点适合做入口节点
Stable flag：directory authority认为该节点适合用作长期虚电路的节点，通常是运行时间长的节点

2.4 选路算法
在默认情况下，Tor选择3个节点作为路由节点，分别为入口节点，中间节点和出口节点。目录服务器中存储了所有节点的基本信息，在进行选路时主要根据节点的带宽大小与运行时间选路。出于效率和稳定性的考虑，Tor倾向于选择带宽大和运行时间长的节点作为路由节点。但同时为了保证负载均衡，在选择中间节点和出口节点时，Tor依据节点带宽的权重进行选择，即节点被选中的概率与其带宽大小成正比。
在选择入口节点时，由于其路由位置的重要性（与用户直接相连，一旦入口节点妥协，则攻击者就能知道用户的真实身份），Tor采用了“Entry guard”机制。每个客户端根据节点带宽和稳定性（运行时间）选择一些节点作为守卫节点，在之后的一段时间内，该客户端在建立虚电路时只从守卫节点中选择一个作为入口节点。这种方法虽然不能从根本上杜绝入口节点妥协的情况，但是对于那些选择了好的守卫节点的客户端，可以保证在接下来一段时间内通信的匿名性；即使不幸守卫节点中有被妥协的节点，也不会比不使用“Entry guard”的情况更糟糕。

2.5 hidden service
Tor为服务器提供了名为hidden service特殊的保护机制，目的是保护服务器的IP地址以防止其泄露。客户端访问hidden service时使用随机生成的后缀为.onion域名，防止信息泄露。
Hidden service通过它随机选取的几个introduction point作为它的联系点，隐藏自己的IP地址并公布所有introduction point的IP地址。客户端想要访问hidden service，需要选取一个洋葱路由作为其rendezvous point，然后连接hidden service的其中一个introduction point，告知hidden service客户端的rendezvous point，之后客户端与hidden service之间的通信都需要通过rendezvous point来完成。具体步骤如下：
  1. Hidden service选择几个introduction point，并与他们之间分别建立虚电路
  2. Hidden service建立与目录服务器的虚电路，并告知服务描述符号，包括hidden service的公钥和introduction point的信息。然后hidden service可以公布它后缀为.onion的域名吸引用户访问
  3. 当客户端想访问某个hidden service，客户端建立与目录服务器的虚电路并获取相关的hidden service信息，包括introduction point信息
  4. 客户端选择一个rendezvous point并建立一条虚电路，并发送cookie
  5. 客户端选择其中一个introduction point建立虚电路，并发送相关信息包括rendezvous point信息、cookie和DH算法的前一半密钥
  6. 一旦客户端得知introduction point已收到相关信息，就拆除到introduction point的虚电路
  7. introduction point收到客户端信息后，将其重新打包发送到hidden service
  8. hidden service收到信息后，生成DH算法另一半密钥。然后建立一条到rendezvous point的虚电路，并发送DH算法的后一半密钥、哈希值和cookie
  9. rendezvous point收到信息后，将客户端和hidden service的cookie匹配后，将DH算法的后一半密钥、哈希值和cookie重新打包发送到客户端
  10. 客户端收到信息后，生成会话密钥，并通过哈希值验证，这样客户端和hidden service完成握手，建立一条经过rendezvous point的虚电路，可以建立数据流
 

3.	匿名性
通常对于匿名网络来说，攻击者的攻击目的是发现消息收发端的身份及通信关系。由于Tor的目标定位是可以大规模部署的低延迟匿名网络，对效率和扩展性方面有较高的要求，而且允许任何人在Tor网络中布置自己的路由节点，这导致了Tor无法实现强匿名性，即Tor无法应对攻击者在控制大量Tor网络节点后进行的全局攻击的情况。
从Tor的设计上可以看出，虚电路上的每一个节点都只知道自己的前任节点和后继节点的身份，因此入口节点可以知道发送的IP地址，出口节点可以知道接收端的IP地址，假设攻击者同时控制了入口节点和出口节点，那么他就可以通过某些被动分析或主动分析的攻击方法，通过入口节点和出口节点来关联发送端和接收端。
被动分析的方法包括以下几种（Erdin, Esra, C. Zachor, and M. H. Gunes. "How to Find Hidden Users: A Survey of Attacks on Anonymity Networks." IEEE Communications Surveys & Tutorials 17.4(2015):2296-2316.）：
	交叉攻击：攻击者通过持续观测并记录用户的网络行为，并进行交叉排除，最后锁定Tor用户的身份以及用户之间的通信关系。用户的网络行为可能包含多种：如用户在浏览网页时遵循的某种模式、用户上下线的时间、邮件服务等。这种攻击方式通常需要攻击者有潜在的怀疑对象的集合，并从中进行排除，最终得到结果。
	流量模式关联：攻击者通过识别并记录入口节点和出口节点的流量特征，然后将通信双方的流量模式进行关联，最终得到消息的发送端与接收端的通信关系。流量特征一般包括：时间特征、数据包数量、数据的封包方式等
	网站指纹识别：访问不同网站时，产生的流量特征不同，攻击者可以根据这点建立网站的指纹数据库。当用户访问某网站时，可以在入口节点处捕获流量，并与指纹数据库进行匹配，最终得到该用户访问某网站这一事实。
主动分析的方法包括以下几种：
	伪造流量：攻击者虽然无法自己生成Tor流量，但是可以对原有流量进行改变。比如：复制某个cell、删除某个cell、插入一个cell、改变某个cell，这些方式都会导致传输出错，并将错误传播到出口节点，然后调用Tor的错误处理机制，拆除虚电路。攻击者可以通过识别错误信号进而关联同一虚电路上的入口节点和出口节点，从而发现用户间的通信关系
	标记攻击：攻击者可以在不改变源流量的情况下，在流量中插入某种信号，然后在出口节点处识别该信号，进而得到通信关系。例如，利用Tor的数据封包方式，通过数据包中包含cell的数量来对信号进行编码，然后在出口节点处识别。
	拥塞攻击：攻击者通过增大某一节点的负载，然后来观测虚电路的拥塞状态，看虚电路是否受到影响，可以判断出虚电路是否经过该节点。通过这种方式可以发现整条虚电路的路径。
	DoS攻击：攻击者通过对Tor网络中的正常节点进行DoS攻击后，使其瘫痪，然后减小网络规模，提高恶意节点被选为入口节点和出口节点的概率，从而更容易使攻击成功。

3.1 cell计数攻击（Ling, Zhen, et al. "A new cell counter based attack against tor." ACM Conference on Computer and Communications Security ACM, 2009:578-589.）
OR内部的工作模式如下图：
 
原理：当OR接收到数据流时，经过传输层的解析后，得到chunk的序列，一个chunk中可能包含一个或多个cell，每个cell经过OR的处理后，得到新的cell保存在输出缓冲区中，此时cell需要被重新打包成chunk，然后输出。因此可以通过对cell采用不同的打包方式，在流量中插入编码。
前提：攻击者已经控制入口节点和出口节点
方法：本攻击可以从入口节点或出口节点处发起，下面假设从出口节点发起攻击：
step 1：出口节点收到cell_created和cell_relay_connected，得知接下来的cell序列都是cell_relay_data，因此执行step 2
step 2：攻击者通过数据包的封装方式，向流量中插入一个二进制编码信号，三个cell从队列流出代表“1”，一个cell从队列流出代表“0”
step 3：入口节点收到2个cell_relay_extended和1个cell_relay_connected，便得知接下来的序列都是cell_relay_data，因此开始记录到达的cell
step 4：攻击者在入口节点处识别该信号，并将消息发送者和接收者的IP关联起来

3.2 重放攻击（Pries, R., et al. "A New Replay Attack Against Anonymous Communication Networks." IEEE International Conference on Communications IEEE, 2008:1578-1582.）
原理：由于Tor通信时使用计数模式的AES加密，因此如果在通信时复制任意cell，则会导致消息的解码失败，可以在出口节点处捕获这一事件，然后通过时间关联入口节点和出口节点，进而关联消息的发送端与接收端
前提：攻击者已经控制入口节点和出口节点，并有一台中央服务器
方法：
step 1：入口节点复制cell，同时记录并上传源IP和复制时间，这里注意复制的cell不能是虚电路建立时的cell，否则会导致协议错误进而立刻拆除虚电路，这样通信双方的通信关系尚未建立，因此只能复制relay阶段的cell。
step 2：出口节点在处理被复制的cell时会出现解码错误，此时记录并上传目的IP和发现时间
step 3：使用Network Time Protocol（NTP）对这两个事件进行时间关联，进而得到消息发送端和接收端的通信关系

3.3 协议级hidden service发现（Ling, Zhen, et al. "Protocol-level hidden server discovery." INFOCOM, 2013 Proceedings IEEE IEEE, 2013:1043-1051.）
原理：hidden service在接收到损坏的数据包时，会根据Tor协议拆除到汇聚点的虚电路，入口节点可以通过捕获拆除虚电路时发送的cell序列进而识别出该事件，然后在时间上进行关联，发现hidden service正在使用攻击者控制的节点作为入口节点，这样攻击者就能知道hidden service的IP地址
前提：控制一些入口节点，一个客户端，一个汇聚点，一台中央服务器用来记录数据
方法：
step 1：Tor客户端从目录服务器获取hidden service的介绍点信息，然后建立到介绍点的虚电路，并告知中央服务器发现开始
step2：hidden service建立到汇聚点的虚电路，如果hidden service选取我们控制的入口节点，入口节点会收到相应的数据包序列，具有协议特性，入口节点收到该序列的数据包后向中央服务器报告相关信息。最后汇聚点会收到Relay_Command_Rendezvous。但这并不一定表示hidden service选择了我们的入口节点，以下步骤来验证这一假设
step 3：一旦客户端和hidden service的连接建立，客户端会向hidden service发送数据，但汇聚点此时会操纵数据包，向hidden service转发一个损坏的数据包，汇聚点同时向中央服务器报告这一行为
step 4：损坏的数据包到达hidden service后，无法正确解密数据包，因此它会拆除虚电路并发送相应的数据包，这个数据包会穿过整条路径到达客户端，入口节点在接收到该数据包时会向中央服务器报告，汇聚点也会检测到这一数据包并向中央服务器报告
step 5：为了判断hidden service是否选择我们的节点作为入口节点，中央服务器查询并比较以下三个记录的时间：汇聚点发送损坏数据包、汇聚点接收到拆除数据包、入口节点接收到拆除数据包。一旦三个记录的时间关联被发现，我们就能通过入口节点获得hidden service的IP地址

4.	Tor安全机制
虽然Tor无法应对全局攻击，但Tor自身也提供了一些机制来加强匿名性，包括以下几点：
周期性的更换密钥：防止密钥泄露的情况
数据包大小固定：杜绝一切通过识别数据包大小的攻击方式
每隔10分钟更换虚电路：可以有效防止一些需要进行长期观测才能成功的攻击方法
Entry guard：可以一定程度上防止入口节点被攻击者控制的情况
多个用户可以共享同一条虚电路：这种方法不但对Tor网络的效率有所提升，而且由于多个用户的流量混杂到一起，增大了攻击者的攻击难度
漏管式的拓扑结构：允许流量在虚电路中途离开，有效防止攻击者在虚电路出口通过观测流量模式等攻击方式
目录服务器主动测量节点带宽：攻击者经常会通过虚报节点的带宽来使节点更容易被选为入口节点或出口节点，因此目录服务器会周期性的主动测量网络中每个路由节点的带宽。但这种方式的弊端是会增加网络负载。

