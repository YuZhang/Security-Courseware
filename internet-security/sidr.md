# 域际路由安全

本节学习三个方面与BGP安全相关内容：

1. 抵御DoS攻击的BGP黑洞技术（不是BGP本身安全问题，是利用BGP解决安全问题）
2. 路由泄露检测与防御
3. BGP操作安全

## 1. 抵御DoS攻击的BGP黑洞技术

BGP黑洞（BGP blackholing）：利用BGP协议来限制指定目标IP地址的流量，通常用于缓解DoS攻击。

### 1.1 [RFC7999: Blackhole Community (2016)](https://www.rfc-editor.org/rfc/rfc7999.txt)

一个起源AS利用“BLACKHOLE”团体属性令邻居AS丢弃以指定IP前缀为目的的流量。利用定义的团体属性实现黑洞的好处是有统一标准会更容易地实现和监测黑洞。

- 团体（community）属性可以添加在每一个路由前缀中，由RFC1997定义，是一个transitive optional属性。包含有团体属性的路由，表示该路由是一个路由团体中的一员，该路由团体具有某种或多种相同的特征。
- 黑洞团体注册为：一个"BGP Well-known Communities" `BLACKHOLE (= 0xFFFF029A)`，其中最低两个16进制数对应的十进制是666，这是网络运营商常用的值。
- 当一个网络遭受DDoS攻击时，该网络可以声明一个涵盖了受害者IP地址的IP前缀，该声明附带BLACKHOLE团体属性，来通知邻居网络任何以该IP地址为目的的流量都应该被丢弃。
- BLACKHOLE团体可以用来触发基于目的的远程触发黑洞（RTBH）[RFC5635](https://tools.ietf.org/html/rfc5635)。
- 局部黑洞：当一台路由器收到带有黑洞团体属性的路由声明时，应该添加`NO_ADVERTISE`（0xFFFFFF02，该路径禁止被通告给其他相连路由器）或`NO_EXPORT`（0xFFFFFF01，该路径禁止被通告给AS或联盟外部的路由器）团体来组织该前缀被传播到本自治域之外。
- 接受黑洞IP前缀：
	- 通常BGP路由器不会接受长度大于/24 (IPv4)和/48 (IPv6)的声明。但黑洞前缀长度应该尽可能的长来防止未被攻击的IP地址收到影响。通常，黑洞前缀采用/32 (IPv4)和/128 (IPv6)。
	- 一个AS声明的黑洞前缀应该被该AS有权声明的前缀所覆盖。
	- 接收方已经同意在特定BGP会话中接受BLACKHOLE团体。

### 1.2 [DE-CIX黑洞服务 (2018)](https://www.de-cix.net/en/resources/de-cix-blackholing-guide) [[幻灯片]](https://www.de-cix.net/_Resources/Persistent/4277e7d4867a78ae923c0f5b3b66d7ff6aeb61f8/DE-CIX-Blackholing-Service.pdf)

### 1.3 BGP黑洞测量

论文：Inferring BGP Blackholing Activity in the Internet, IMC'17. (2017) [[论文]](https://conferences.sigcomm.org/imc/2017/papers/imc17-final90.pdf) [[幻灯片]](https://conferences.sigcomm.org/imc/2017/slides/IMC2017-BGP-Blackholing.pdf) ：

开发并评估了一种自动检测现实网络中BGP黑洞活动的方法，应用于公共和私有BGP数据集发现，包括大型transit提供商在内的数百个网络，以及约50个互联网交换点（IXP）或黑洞服务商为其客户，对等体和成员提供服务。在2014-2017年之间，黑洞前缀数量增加了6倍，达到5K，同时来自400个自治域。使用定向主动测量和被动数据集来评估数据平面上黑洞效果，发现在到达黑洞目的地之前丢弃流量确实非常有效，尽管它也丢弃了合法流量。

## 2. 路由泄露防御

参考资料：

- [RFC7908: Problem Definition and Classification of BGP Route Leaks (2016)](https://tools.ietf.org/html/rfc7908)
 [Internet Draft: Route Leak Prevention using Roles in Update and Open messages (2018)](https://tools.ietf.org/html/draft-ietf-idr-bgp-open-policy-02)
- [Internet Draft: Methods for Detection and Mitigation of BGP Route Leaks (2018)](https://tools.ietf.org/html/draft-ietf-idr-route-leak-detection-mitigation-08)

### 2.1 定义与分类

- 路由泄露（route leak）：超过了预期范围的路由声明扩散。
	- 从一个AS到另一个AS的路由声明违背了接收者、发送者和/或之前AS路径上某个AS的预期政策。预期范围通常由本地的重发布/过滤政策来定义，这些预期政策又通常以AS间互联商业关系来定义。
- 提供商-客户(Provider-Customer, P2C)：客户向提供商付费，提供商为客户提供传递Transit服务；客户不为提供商间传递流量。
- 对等(Peer-Peer, P2P)：AS间相互(Peering)传递流量，互不付费；不为各自的其他对等AS或提供商传递流量。
- 无谷(Valley-free)模型：一条AS路径中在P2C或P2P之后不存在C2P或P2P。

下图示例：AS0发出路由声明，其provider、peer和customer违背无谷原则将该路由声明泄露给AS4、AS5、AS7、AS8。

```
                     AS1
                      |
                      |
         AS2 -----[provider]    AS4 [Leak]
                    / |          |
    [Leak]        /   |          |
    AS7       AS3    AS0 -----[peer]----- AS5
       \---\          |          |     [Leak]
            \-----\   |          |
       AS8 -------[customer]    AS6
     [Leak]           |
                      |
                     AS9
```
下面来根据分类的名字来猜一猜，路由声明被泄露给了那个AS？

- Type 1：带有全部前缀的发卡弯（Hairpin Turn with Full Prefix）
- Type 2：横向ISP-ISP-ISP泄露（Lateral ISP-ISP-ISP Leak）
- Type 3：提供商前缀泄露给对等（Leak of Transit-Provider Prefixes to Peer）
- Type 4：对等前缀泄露给提供商（Leak of Peer Prefixes to Transit Provider）
- Type 5：带有通往合法起源路径的前缀重组织（Prefix Re-origination with Data Path to Legitimate Origin）
	- 一个多宿主AS将从一个provider获得的一个路径声明，以自己为起源（去掉路径）重新组织前缀，并声明给另一个provider。然而，该AS以某种方式建立了一条通往真正起源AS的反向路径。因此，数据包仍然可以到达真正起源AS。
- Type 6：内部或更具体前缀泄露（Accidental Leak of Internal Prefixes and More-Specific Prefixes）
	- 一个AS将内部前缀泄露给provider或peer。泄露的前缀通常比已经声明的前缀更具体。

```
Intended blank space






```

- 答案：AS7、AS5、AS8、AS4、AS7、

下面介绍两种正在研究中的路由泄露防御手段。一种是AS内部防止泄露路由给邻居；另一种是检测来自邻居AS的路由泄露。

### 2.2 基于角色的路由泄露阻止

- 参考文献：[Internet Draft: Route Leak Prevention using Roles in Update and Open messages (2018)](https://tools.ietf.org/html/draft-ietf-idr-bgp-open-policy-02)

- 思路：在BGP中AS间商业关系通过各自配置来实现，而路由器间缺乏对关系的协商。因此，一种思路是在BGP中直接加入角色概念，在两个BGP路由器在OPEN消息中对其所在AS间角色/关系达成一致。随后传播的UPDATE信息根据该角色/关系来用一个属性标记，从而阻止路由泄露。

- BGP角色：BGP会话中一个新的可配置选项来反映对互联关系所达成的一致，可取值：
	- 0 Peer：发送方和邻居是peer；
	- 1 Provider：发送方是provider；
	- 2 Customer: 发送方是customer；
	- 3 Internal：发送方和邻居属于同一组织。
		- iBGP会话只能配置Internal角色。
	- BGP Role Capability Code：
		- Type: TBD;
		- Length - 1 (8位)；
		- Value：对应BGP Role的整数
- 在OPEN消息中以Capability选项来传递（[RFC5492](https://tools.ietf.org/html/rfc5492)）。
- 角色检查：当收到对端发过来的角色能力时，检查自己的角色是否匹配？
	- 发送方 --- 接收方
	- Peer  --- ？
	- Provider --- ？
	- Customer --- ？
	- Internal --- ？
	- 若发现不匹配，则必须发送一个NOTIFICATION消息 (代码 2, 子码 <TBD>)。
	- Strict mode：一个新的BGP配置选项，true或false。
		- 若配置为true，则当角色不匹配时，必须拒绝建立BGP会话，发送Connection Rejected Notification (错误码6，子码5) ([RFC4486](https://tools.ietf.org/html/rfc4486))
- 为阻止路由泄露，在UPDATE消息中添加一个新的非传递路径属性iOTC（Internal Only To Customer，只能发送给内部/客户），该属性只是一个标记。iOTC使用规则如下：
	- 若接收方角色为Customer或Peer，则iOTC属性必须被添加到所有收到的路由中；
		- 标记来自于Provider或Peer的路由
	- 若发送方角色为Customer或Peer，则禁止声明带有iOTC属性的路由消息；
		- 不能将iOTC路由发送给Provider或Peer，即禁止路由泄露
	- 禁止非Internal的发送方在UPDATE消息中添加iOTC属性。
		- iOTC属性由接收方添加
	- 若从eBGP收到包含iOTC属性的UPDATE消息，且接收方角色非Internal，则该属性必须被移除。
		- iOTC属性不能被传递
- 问题：为什么不通过Community，而通过Attribute来实现？
	- 对关系达成一致应该在OPEN中实现。无论配置是否错误，路由器应强制实现该关系。
	- 在使用iOTC的路由传播中的关系应该被强制执行，并且应最小化被错误配置的可能。
	- Community通常由网管配置/更改，并且很容易配置错误或被错误过滤；而Attribute通常不会被网管修改，并由路由器强制执行。

### 2.3 基于路由标记的路由泄露阻止

参考资料：[Internet Draft: Methods for Detection and Mitigation of BGP Route Leaks (2018)](https://tools.ietf.org/html/draft-ietf-idr-route-leak-detection-mitigation-08)

- 思路：在路由声明中添加一个RLP（Route-Leak Protection）标记，带有该标记的路由信息被禁止“向上或横向”（向Provider或Peer）传播。当向Customer或Peer发送路由声明时添加该标记，此后若被“向上或横向”传播，则为路由泄露。

- RLP属性：一个新的BGP可选传递属性。类型码待定；长度占8位；
	- 数值为一个ASN（32位）和RLP字段（8位）对的序列，格式如下图；
	- RLP字段缺省为0，即未设定；为1时，“禁止向上或横向传播”；
	- AS_PATH上每个支持RLP的AS插入自己的`{ASN, RLP}`字段；（排除prepending）
	- 因此如果所有AS都支持，则AS_PATH和RLP属性中AS列表应该一致；否则，RLP会缺失若干AS；

```
   +-----------------------+ -\
   | ASN: N                |   |
   +-----------------------+    >  (Most recently added)
   | RLP: N                |   |
   +-----------------------+ -/
    ...........
   +-----------------------+ -\
   | ASN: 1                |   |
   +-----------------------+    >  (Least recently added)
   | RLP: 1                |   |
   +-----------------------+ -/
```

- 接收方检测路由泄露：
	- 一条路由更新同时满足如下条件，则标记为路由泄露：
		- 更新来自于customer或peer
		- 除最近一跳外，一跳或多跳的RLP字段为1（即禁止向上或横向传播）
 	- 排除“最近一跳”的原因在于，接收方应该检查“最近一跳”的前一跳是否设置了RLP来判断是否发生路由泄露；而且接收方已经知道更新来自于customer或peer。

- 当检测到路由泄露后，接收方可按如下方法缓解路由泄露： 
	- 若来自customer或peer的更新被标记为“路由泄露”，则接收方应该优先选择其他未被标记的替代路由；
	- 若没有未被标记的替代路由，则一个被标记为“路由泄露”的路径也可以被接受。
	- 基本原则是，若一个AS收到并标记了一个来自customer的路由为“路由泄露”，则这个AS应该否决“客户优先”（prefer customer）政策，并且优先选择其他“干净”的路由。这可以通过调整“Local preference”来实现。

- Role与RLP比较：
	- AS内部限制输出 vs. AS外部检查输入
	- AS粒度 vs. 前缀粒度
	- 需所有AS支持 vs. 向后兼容（不需要所有AS都支持，但若要防御路由泄露，则大的Provider应支持）

## 3. BGP操作安全

参考资料：

- [RFC7454: BGP Operations and Security](https://tools.ietf.org/html/rfc7454)

摘要：本文档描述了保护BGP会话本身的措施，如生存时间（TTL），TCP认证选项（TCP-AO）和控制平面过滤。描述了使用前缀过滤和前缀过滤自动化，最大前缀过滤，自治系统（AS）路径过滤，路由震荡衰减和BGP团体属性清理来更好地控制路由信息流动。

### 3.1 保护BGP Speaker

- BGP Speaker是实现路由器间BGP会话的组件。
- 威胁：单纯保护TCP是不充分的，例如syn flooding攻击需要采用ACL来防御。
- 主要通过ACL（访问控制列表）予以保护，以丢弃发给本地TCP179端口，但来自未知或非许可的地址的数据包。
- ACL应通过控制平面实现（receive-ACL,、控制平面政策等），避免通过数据平面过滤器实现。
- 一些路由器会根据配置来自动生成ACL；另一些的ACL则需要人工配置
- 速率限制可以用来防止BGP流量过载
- - [RFC6192: Protecting the Router Control Plane](https://tools.ietf.org/html/rfc6192)


### 3.2 保护BGP会话

- 威胁：例如，发送伪造 TCP RST包；通过ARP伪造来在TCP流中注入数据包；
- 保护TCP会话：
	- [RFC5925: The TCP Authentication Option](https://tools.ietf.org/html/rfc5925)：
		- TCP认证选项（TCP-AO）替代RFC 2385中TCP MD5签名选项。
		- 使用更强的消息认证码（MAC），即使对于长时间的TCP连接也能防止重放。
		- 兼容静态主密钥组（MKT）配置或外部带外MKT管理机制；
		- 保护连接重复实例中使用相同MKT时的连接，使用从MKT派生的业务密钥，并且协调终端之间的MKT更改。
	- 保护TCP会话的缺点是需要额外的配置与管理负担，因此并不要求一定实现，即使在IXP共享网络环境下；
	- 希望通过预防源地址伪造来避免这类威胁。
- TTL安全（GTSM）
	- [RFC5082: The Generalized TTL Security Mechanism (GTSM)](https://tools.ietf.org/html/rfc5082)
		- 发送方发送TTL值255，接收方检查TTL值等于255。
		- 非直连子网之外的攻击者的数据包无法以TTL值255到达接收方。

### 3.3 前缀过滤

- 通用前缀过滤器，过滤掉以下前缀：
	- 特殊用途前缀：[IPv4特殊用途前缀](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry), [IPv6特殊用途前缀](http://www.iana.org/assignments/iana-ipv6-special-registry)
	- 尚未分配前缀：
		- IANA已分配前缀：IPv4地址空间已经全部分配，因此无需过滤；IPv6需及时更新
		- RIR已分配前缀：
			- IRR（Internet Routing Registry）数据库，例如[RADb (Routing Assests Database)](http://www.radb.net/)。由RIR和ISP维护的路由信息。
			- SIDR (Secure Inter-Domain Routing)
				- RPKI  ([RFC6480: An Infrastructure to Support Secure Internet Routing
](https://tools.ietf.org/html/rfc6480))，见[课件](bgp-sec.pptx)
				- BGPSec ([RFC7353: Security Requirements for BGP Path Validation](https://tools.ietf.org/html/rfc7353))，见[课件](bgp-sec.pptx)
	- 太长的前缀：多数ISP不接受比/24或/48更长的前缀
	- 过滤属于本地AS和下游的前缀：不需要从外部获得路由信息
	- IXP局域网前缀
	- 缺省路由：0.0.0.0/0
- 对全路由（Full Routing）网络的前缀过滤建议：
	- 严格模式/松散模式——是否根据RIR分配来验证 
	- 对peer的过滤器
		- 入界过滤：特殊前缀、IANA为非配、太长、本地AS、IXP前缀，缺省
		- 出界过滤：特殊前缀、太长、IXP前缀、缺省
	- 对customer的过滤器
		- 入界过滤：非customer的前缀，或与peer过滤器相同
		- 出界过滤：特殊前缀、太长、缺省（除非customer希望采纳缺省路由）
	- 对Provider的过滤器
		- 入界过滤：与peer过滤器相同，除了缺省路由
		- 出界过滤：与peer过滤器相同
- 对末端（Leaf）网络的前缀过滤建议：
	- 入界过滤：特殊前缀、太长、本地AS、缺省（或只采纳缺省路由）
	- 出界过滤：只声明本地前缀
- 路由摆动抑制：限制路由更新数量/频率，详见[RFC7196: Making Route Flap Damping Usable](https://tools.ietf.org/html/rfc7196)
- 最大前缀数量：限制来自邻居AS的路由数量
	- Peer：低于互联网中路由数量
	- Provider：高于互联网中路由数量
	- 超过限制后，可以出发日志记录，或关闭会话
- AS路径过滤
	- 只从customer接受包含该cusotmer的路径
	- 不接受包含私有ASN的路径，除非为了实现黑洞
	- 不接受第一个AS不是相连邻居的路径，除非是IXP的
	- 不应以一个非空路径来通告一个起源前缀，除非有意为其提供传递
	- 不应路由泄露
	- 不应改变BGP缺省行为，例如不应接收包含自己ASN的路径
	- [RFC7132: Threat Model for BGP Path Security](https://tools.ietf.org/html/rfc7132)
- 下一跳过滤
	- 缺省情况下，只接受路由信息的发送方为下一跳
	- 在共享网络中互联时，例如IXP，可以通告一个带有第三方（即非声明前缀的路由器）下一跳的前缀。一种典型的情景就是IXP中的路由服务器，只转发路由消息而不转发流量，详见[RFC7947: Internet Exchange BGP Route Server](https://tools.ietf.org/html/rfc7947)。
	- 黑洞也采用第三方下一跳
- 团体属性清理
	- 应清理入界路径中包含自己ASN的团体属性，并只允许这些团体属性作为customer/peer的信令机制
	- 不应删除其他团体属性。

---------------

 