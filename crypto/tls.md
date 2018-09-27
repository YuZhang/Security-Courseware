# 传输层安全

### 哈尔滨工业大学 网络与信息安全 张宇 2016

---

## 1. SSL/TLS简介

### 1.1. 介绍

- [SSL（Secure Socket Layer）/ TLS（Transport Layer Security）](https://en.wikipedia.org/wiki/Transport_Layer_Security)的一个极简介绍：客户端选择一个秘密随机数，使用服务器的公钥加密发送给服务器。客户端和服务器间用这个秘密中派生出的若干加密和MAC密钥来通信。
	- 目的：保护通信的机密性、完整性、真实性（认证）
	- 位于传输层（例如TCP）之上，应用层（例如HTTPS）之下
	- 包括两层：TLS记录（record）协议传输应用数据，TLS握手（handshake）协议实现认证，协商密钥和算法

- 协议演化：
	- 1994和1995年，NetScape公司设计了SSL 1.0和2.0，由[Taher Elgamal](https://en.wikipedia.org/wiki/Taher_Elgamal)设计
	- 1996年，SSL 3.0问世，得到大规模应用
	- 1999年，IETF发布了SSL的升级版TLS 1.0（[RFC2246](https://tools.ietf.org/html/rfc2246)）
	- 2006年和2008年，两次升级分别为TLS 1.1（[RFC4246](https://tools.ietf.org/html/rfc4346)）和1.2（[RFC5246](https://tools.ietf.org/html/rfc5246)）（也被称为SSL3.1和3.2）
	- 2006年，发布基于TLS 1.1的[DTLS 1.0](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)（[RFC4347](https://tools.ietf.org/html/rfc4347)）；2012年，升级到基于TLS1.2的DTLS 1.2（[RFC6347](https://tools.ietf.org/html/rfc6347)）
	- 目前(2016年11月5日)，[TLS 1.3草案](https://tlswg.github.io/tls13-spec/)正在制定
- SSL 2.0缺陷（2011年正式废弃，见[RFC6176](https://tools.ietf.org/html/rfc6176)）：
	- MAC中使用不安全的MD5 
	- 握手消息未被保护，中间人攻击欺骗客户端挑选一个弱密码套件
	- 消息完整性和加密使用相同的密钥，若使用弱的加密算法时会产生问题
	- 会话很容被中断，中间人可通过插入一个TCP FIN来终止
- SSL 3.0缺陷（2015年正式废弃，见[RFC7568](https://tools.ietf.org/html/rfc7568)）：
	- 记录层：[POODLE攻击](https://en.wikipedia.org/wiki/POODLE)利用CBC中非确定性padding来恢复明文
	- 密钥交换：当[重新协商 (RFC5746)](https://tools.ietf.org/html/rfc5746)或[会话继续 (Triple Handshakes)](http://www.mitls.org/downloads/tlsauth.pdf)时受到中间人攻击
	- 定制的密码学基元：定制的伪随机函数（PRF）、HMAC和数字签名等基元缺乏深入的密码学检查；所有基元依赖于SHA-1和MD5都不安全
	- 无法支持新功能，主要包括[AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption)，[ECDH](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie–Hellman)/[ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)，无状态会话ticket，[DTLS](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security)，[应用层协议协商](https://tools.ietf.org/html/rfc7301)
- TLS 1.0与SSL 3.0的关系（[RFC2246](https://tools.ietf.org/html/rfc2246)）
	- 没有巨大变化，但差异导致不兼容
	- 支持版本降级到SSL 3.0，但会被攻击者利用
- TLS 1.1在TLS 1.0基础上改进（[RFC4246](https://tools.ietf.org/html/rfc4346)）
	- 防御针对CBC模式的攻击：用显式初始向量（IV）替代隐式IV
	- 正确处理padding错误
- TLS 1.2在TLS 1.1基础上改进（[RFC5246](https://tools.ietf.org/html/rfc5246)）
	- 用SHA-256替换MD5-SHA-1
	- 用[PSK](https://en.wikipedia.org/wiki/TLS-PSK)和ticket替代会话继续(resumption)
	- 增加AES套件支持，扩展支持认证加密（AE），用于基于AES的[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)（[RFC5288](https://tools.ietf.org/html/rfc5288)，[RFC5289](https://tools.ietf.org/html/rfc5289)）和[CCM](https://en.wikipedia.org/wiki/CCM_mode)（[RFC6655](https://tools.ietf.org/html/rfc6655)）模式
- TLS 1.3（[草案](https://tlswg.github.io/tls13-spec/)）在TLS 1.2基础上改进
	- 对TLS1.2实现有影响的更新：版本降级攻击保护，[RSASSA-PSS](https://en.wikipedia.org/wiki/PKCS_1)
	- 不再支持不常用的弱椭圆曲线，MD5和SHA-224，不安全的压缩，重协商，非AEAD加密，静态RSA和静态DH密钥交换等等
	- 禁用SSL或RC4协商；冻结记录层版本号；即使之前的配置被使用，也须数字签名
	- 集成[HKDF](https://en.wikipedia.org/wiki/Key_derivation_function)，半临时DH，会话哈希，支持1-RTT和0-RTT握手协议
	- 支持新的密码基元，包括[ChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant)流密码，[Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC，[EdDSA](https://en.wikipedia.org/wiki/EdDSA)数字签名算法，[x25519](https://en.wikipedia.org/wiki/Curve25519)密钥交换协议

### 1.2. TLS握手协议

TLS 1.2（[RFC5246](https://tools.ietf.org/html/rfc5246)）:

- 交换hello消息来协商算法，交换随机值，检查会话继续
- 交换密码学参数来协商一个premaster秘密
- 交换证书（[X.509](https://en.wikipedia.org/wiki/X.509) certificate）和密码学信息来进行身份验证
- 从premaster秘密和随机值中生成master秘密，为记录层提供安全参数
- 客户端和服务器验证彼此已经计算了相同的安全参数，握手过程未被篡改

一次完整握手协议的消息流：

```c
   Client                                               Server

      ClientHello                  -------->
          {client_random}
                                                      ServerHello
                                                          {server_random}
                                                     Certificate*
                                                          {ServerPubKey 
                                                           signed by CA}
                                               ServerKeyExchange*
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
          {pre_master_secret
           encrypted by ServerPubKey}
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
                                   
      Application Data             <------->     Application Data
             

 *  Indicates optional messages/extensions that are not always sent.
  
 - master_secret = PRF(pre_master_secret, "master_secret",
                          client_random + server_random)[0..47];
                          
 - Finished: PRF(master_secret, finished_label, Hash(handshake_messages))
```

- RSA握手：如上图所示，客户端选择pms，用服务器公钥加密发给服务器
- DHE（ephemeral DH）握手：服务器将密钥材料（p, g, g^s）用自己私钥签名，客户端将（g^c）发送给服务器，双方计算pms=g^{cs}

### 1.3. TLS记录协议

- 记录协议是一种分层协议；在每一层，消息中包括长度、描述和内容
- 支持4种高层协议：握手（22 handshake），告警（21 alert），变更密码说明（20 change cipher spec），应用数据（23 appication data），心跳（24 Heartbeat）
- 待传递的消息被分片、压缩、做MAC、加密并传递
- 接收到的数据被解密、验证、解压缩、重组，提交到更高层

```   
+———————————————+  1.fragmentation  +———+  +———+———+———+
|    message    |——————————————————>|   |  |   |   |   |
+———————————————+                   +———+  +———+———+———+
                                      | 2.compression
                                      v   
5.transmit +————+    4.encryption    +—+ 3.MAC +———+   
 <—————————|XXXX|<———————————————————| |———+———|tag|
           +————+                    +—+       +———+  
```

- 连接状态（connection states）：执行记录协议的操作环境
	- 压缩算法，加密算法，MAC算法，加密密钥与材料，序列号等
	- 握手协议完成后，根据安全参数传递生成的对称加密密钥和加密材料：
		- `key_block = PRF(master_secret, "key expansion", server_random + client_random);`
		- 从`key_block`中提取客户端-->服务器加密密钥、MAC密钥、IV
		- 从`key_block`中提取服务器-->客户端加密密钥、MAC密钥、IV

### 1.4 重新协商（Renegotiation）

- 客户端或服务器可在已经建立的TLS连接上请求新的握手，例如临时需要客户端验证
- 该过程与之前的握手过程一样，除了消息都是通过在已建立的连接上加密传递
- 握手完成后，双方以新协商的参数开始一个新的会话

## 2. 针对SSL/TLS的攻防

针对TLS的攻击总结：[RFC7457: Summarizing Known Attacks on Transport Layer Security (TLS) and Datagram TLS (DTLS)](https://tools.ietf.org/html/rfc7457)

TLS安全使用建议：[RFC7525 (BCP195): Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)](https://tools.ietf.org/html/rfc7525)

###  2.1. SSL Stripping

由[Moxie Marlinspike](https://en.wikipedia.org/wiki/Moxie_Marlinspike)发明，通过中间人攻击更改未加密的HTTP流量或网页来剥离SSL/TLS，详见[New Tricks For Defeating SSL In Practice (Blackhat DC 2009)](http://www.blackhat.com/presentations/bh-dc-09/Marlinspike/BlackHat-DC-09-Marlinspike-Defeating-SSL.pdf)。

[降级攻击（Downgrade）](https://en.wikipedia.org/wiki/Downgrade_attack)：令计算机系统或通信协议不采用新的高质量的，而是采用旧的低质量的操作模式；后者通常是为了与旧系统向后兼容。

- 用户通常在浏览器地址栏直接输入网址（`www.foo.com`），而不带有协议头（`https:`）
- 浏览器将URL自动填写为`http://www.foo.com`，并向foo.com发送请求
- foo.com用HTTP 302重定向将URL指向`https://www.foo.com`
- 攻击者劫持指向`https`的重定向消息，一方面伪装成用户与foo.com建立`https`连接，另一方面伪装为服务器与浏览器继续`http`会话

```
   Client                   Attacker                   Server
   ------                   --------                   ------
   <----------------------    HTTP   ----------------------->
   <---------HTTP--------->   strip  <========HTTPS=========>
```

对策：[RFC6797: HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797) 

相关论文：[ForceHTTPS: Protecting High-Security Web Sites from Network Attacks (WWW 2008)](https://crypto.stanford.edu/forcehttps/)

- 服务器在HTTPS连接中的HTTP头部添加一个新域：`Strict-Transport-Security: max-age=31536000; includeSubDomains`
- 客户端设置一个cookie，在`max-age`指定的时间（例如1年）内，自动将访问该网站的任何`http`链接转换为`https`
- 用户首次访问时并未被HTTPS保护，攻击者可将HSTS头部去掉；对策是在浏览器内预制一批HSTS站点

### 2.2. BEAST

参考资料：[“Here Come The ⊕ Ninjas”](https://bug665814.bmoattachments.org/attachment.cgi?id=540839)

BEAST (Browser Exploit Against SSL/TLS)（[CVE-2011-3389](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3389)）攻击针对TLS 1.0中CBC实现中可预测的初始向量（chaining IV）来破解报文，IV为前一个密文中的最后一个块，而不是新产生的随机串。

在选择明文攻击下，攻击者可猜测一个之前观察到的明文块`P_i`是否为`x`?

- CBC加密：`C_1 = E(IV xor P_1)`, `C_i = E(C_(i-1) xor P_i)` 
- CBC解密：`P_1 = D(C_1) xor IV`, `P_i = D(C_i) xor C_(i-1)`
- chaining IV：`IV`=前一个密文中的最后一个块，可以想象消息被串成一串
- 选择下个消息的首个明文块`P_j = C_(j-1) xor C_(i-1) xor x`
- 若`P_i = x`，则`C_j = E(P_j xor C_(j-1)) = E(C_(i-1) xor P_i) = C_i`

```
 IV    P_(i-1)    P_i       P_(j-1)   P_j = C_(j-1) xor C_(i-1) xor x
 |      |          |           |          |
 |      v          v           v    IV'   v
 +———> xor  +———> xor  +— ...  +   +———> xor ...
 |      |   |      |   |       |   |      |
 |     E_k  |     E_k  |      E_k  |     E_k
 |      |   |      |   |       |   |      |
 |      |———+      |———+  ...  |———+      |  ...
 v      v          v           v   v      v
 IV    C_(i-1)    C_i         C_(j-1)    c_j
```

实践中，攻击者可结合跨站请求伪造（CSRF）攻击来获取HTTPS保护下的secure cookie。

- 假设攻击者可窃听HTTPS流量，否则没必用使用HTTPS来保护cookie
- 当用户访问攻击者网站时，攻击者网页脚本访问目标网站，用户向目标网站发送带有cookie（cookie­-bearing）的请求
- 攻击者利用浏览器技术，例如HTML5 WebSocket（v76），可获得以下能力：
	- 选择块边界（Boundary）：在请求串前附加若干比特，例如`ABCDEF`，来指定块边界
	- 按块选择（Blockwise）：利用`send()`来指定选择明文攻击的明文块

```js
var s = new WebSocket("wss://bob.com/websocket?ABCDEF");
s.onopen = function(e) {    console . log (" opened ");
    s.send("Hello, world!");
    s.send("Here come the + ninjas");}
```

破解请求头部中cookie的攻击步骤：

- Step 1：攻击者令用户发送请求`POST /AAAAAA HTTP/1.1<CR><LF><REQUEST HEADERS><CR><LF><REQUEST BODY>`，被CBC模式加密后，发送给目标服务器。
- Step 2: 攻击者获取所有密文，明文块`P_3`为`P/1.1<CR><LF><X>`，`X`是待猜测内容。
- Step 3: 攻击者将`P_guess = C_last(IV) xor C_2 xor "P/1.1<CR><LF><Y>"`附加在`<REQUEST BODY>`前，用户加密后将`C_guess`发送给服务器。
- Step 4: 若`C_guess = C_3`，则`X = Y`；否则，改变`Y`并跳到Step 3。

防御：[TLS 1.1中方案](https://tools.ietf.org/html/rfc4346#page-21)

- 一种直接的方法是每次产生新的随机IV
- 另一种方案：产生随机数R，将其附加为明文的第一块；IV仍为前一个密文的最后一块
	- 好处一是保留与TLS 1.0的代码兼容性
	- 好处二是避免快速重置IV，引文已知部分系统在此存在问题

### 2.3. Padding Oracle攻击


[Padding Oracle攻击](https://en.wikipedia.org/wiki/Padding_oracle_attack)：一种选择密文攻击（CCA）

- 加密时在明文后填充（padding）数据令消息长度为块长整数倍
- 解密时若发现padding有错误，则返回错误消息
- 攻击者篡改密文，根据是否返回错误消息，来判断特定位置明文的内容
	- 若无错误，则说明padding格式正确

#### POODLE

[POODLE（Padding Oracle On Downgraded Legacy Encryption）](https://en.wikipedia.org/wiki/POODLE)（[CVE-2014-3566](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566)）攻击针对SSL 3.0中CBC模式下非确定、可篡改的padding方案：

- 被CBC加密消息：明文 ‖ MAC(明文) ‖ Padding
- padding长度L，padding内容：L-1个字节 ‖ L-1
	- SSL 3.0中内容可为任意字节
	- 例如，块长8字节，末块明文1字节，则L=7，填充 a，b，c，d，e，f，6
- 当明文+MAC长度恰好是块长（16字节）整数倍，附加一个哑块（dummy block）：15个字节 ‖ 15
- Padding是非确定的，因为除末尾长度外的其他内容随意
- Padding完整性未被MAC保护

可实施padding oracle攻击来解密一个字节`X`：

- 令明文+MAC长度恰好是块长整数倍，填充一个哑块最后一个字节为15，对应最后一个密文块为`C_n`
- 用以`X`结尾名为`P_i`对应密文块`C_i`替换`C_n`，发送给服务器
- 若服务器未返回错误，意味着解密出最后一块明文末字节=15
	- `15 = {D(C_i) xor C_(n-1)}[15]`
	- `D(C_i) = 15 xor C_(n-1)[15]`
	- `X = D(C_i) xor C_(i-1)[15]`
	- `X = 15 xor {C_(n-1) xor C_(i-1)}[15]`
- 若发生错误，则攻击者构造新`P_i`来加密，用新`C_i`来重复之前步骤

实践中，采用与之前BEAST类似技术，攻击者获取HTTPS保护下的secure cookie：

- 伪造请求：`POST /path Cookie: name=value...\r\n\r\nbody`
- 通过控制`/path`长度来选择待破解字节`X`并令`X`位于`P_i`块末尾
- 通过更改`/path`内容来构造不同`P_i`令解密时不报错

防御：在TLS 1.1中，

- padding填充内容都为确定值L-1，令攻击者难以构造有效padding
- 用"bad record mac"告警替换掉原来的"decryption failed"告警，即只说密文完整性被破坏，而不泄露是否解密失败（padding error）


#### Lucky Thriteen

论文 [“Lucky Thirteen: Breaking the TLS and DTLS Record Protocols (USENIX Security 2013)”](http://www.isg.rhul.ac.uk/tls/Lucky13.html)

[计时攻击（timing attack）](https://en.wikipedia.org/wiki/Timing_attack)：一种旁路攻击，利用密码学算法所消耗时间来进行密码分析。

[幸运十三攻击](https://en.wikipedia.org/wiki/Lucky_Thirteen_attack)：Padding不同->解密出明文长度不同-->MAC验证消耗时间不同（以55字节为界）-->返回错误消息时间不同。该攻击理论意义大于实践。(”十三“源自消息头部长度为13字节)

防御：添加随机延迟。

### 2.4 压缩攻击

#### CRIME

[CRIME](https://en.wikipedia.org/wiki/CRIME)（Compression Ratio Info-leak Made Easy）（[CVE-2012-4929](http://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2012-4929)）：根据TLS压缩会将重复字符串变短的原理，实施选择明文攻击。由BEAST攻击的作者开发。

[DEFLATE压缩算法](https://en.wikipedia.org/wiki/DEFLATE)（[RFC1951](https://tools.ietf.org/html/rfc1951)）：通过删除冗余信息进行无损压缩，被zip和gzip采用

- [LZ77](https://en.wikipedia.org/wiki/LZ77_and_LZ78)：扫描输入，寻找重复字符串，用反向引用（到上一次出现的距离和长度）替换
	- 例子：`Google is so googley` -> `Google is so g(-13, 5)y`
- [哈夫曼编码（Huffman coding）](https://en.wikipedia.org/wiki/Huffman_coding)：以更短的编码来替代更频繁的公共串
- 压缩比（Ratio）：越冗余，压缩越小，比例越高

攻击思路：选择明文攻击，攻击者可控制部分输入，观察压缩后长度变化

- 观察不同`input`下的`len(compress(input + secret))`
- 若`len`变短，则说明`input`和`secret`中包含冗余

SSL/TLS加密过程并不隐藏消息长度，即泄露了`len(encrypt(compress(input + public + secret))`

- `input`：URL path；`secret`：cookie
- `input`中尝试不同猜测，令浏览器发送包含`secret`的加密请求
- 观察请求长度`len`变化，正确的猜测会令`len`变短

请求示例：

```html
GET /twid=aHost: twitter.com
User-Agent: Chrome
Cookie: twid=secret 

...
GET /twid=sHost: twitter.com
User-Agent: Chrome
Cookie: twid=secret
```
攻击效果：

- 可攻击45%的浏览器（Chrome, Firefox），所有SPDY服务器（Gmail，Twitter等），40%的SSL/TLS服务器（Dropbox，GitHub等）
- JavaScript可选，平均6个请求可破解1字节cookie，对所有TLS版本和加密套件可行

攻击细节：

- 攻击者所获得的长度以字节为单位，但DEFLATE输出比特，因此至少8比特差异才能导致长度不同。
- DEFLATE算法一个重要参数是窗口大小，重复字符串在在窗口内搜索；若重复串距离超过窗口大小则不会被替换。

首次攻击需两次尝试（两次请求）：

- req1：猜测和cookie在同一窗口内
	- `GET /ABCDEFtwid=s<padding>Cookie: twid=secret`
- req2：猜测和cookie不在一个窗口
	- `GET /twid=sABCDEF<padding>Cookie: twid=secret`
- 若猜错，则不会被替换，因此`len(req1)==len(req2)`
- 若猜对，则req1中被替换，因此`len(req1) != len(req2)`
- Oracle：若长度不同，则猜测正确

- 优点：没有误报
- 缺点：cookie中包含重复串可能导致失效，需要构造8比特差异

TLS中压缩：

- [RFC3749](https://tools.ietf.org/html/rfc3749)中说明了DEFLATE，[RFC3943](https://tools.ietf.org/html/rfc3943)中说明了LZS
- Chrome（[NSS](https://en.wikipedia.org/wiki/Network_Security_Services)），OpenSSL，GnuTLS中实现了DEFLATE
- 若数据被分片（16K字节），则每个记录独立压缩

攻击方法：16K-1

1. 创建一个足够大的随机请求，该请求将被分割为2个记录
	- 第1个记录：`GET /<random-padding>Cookie: twid=s`
	- 第2个记录：`ecret`
- 对每个候选值x，模拟压缩第1个记录`...twid=x`，获得长度
- 发送请求，获得第1个记录压缩后长度，有相同长度的候选值可能是真实值
- 重复上述过程，直到确定唯一候选值

16K-1 POC：

```python
def next_byte(cookie, known, alphabet=BASE64):
	candidates = list(alphabet)	while len(candidates) != 1:		url = random_16K_url(known)		record_lens = query(url)		length = record_lens[0]		record = "GET /%s%s%s" (url, REQ, known)
		good = []		for c in candidates:			if len(compress(record + c)) == length:				good.append(c)
		candidates = good	return candidates[0]
```

- 优点：无误报；压缩算法无关
- 缺点：40%服务器端支持TLS压缩，浏览器只有Chrome支持TLS压缩；攻击者和受害者的zlib版本必须一致

相关攻击：

- [BREACH](https://en.wikipedia.org/wiki/BREACH_(security_exploit))（Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext）：利用HTTP压缩实施攻击，详见[BREACH主页](http://breachattack.com)。
- "HEIST: HTTP Encrypted Information can be Stolen through TCP-windows"，该攻击通过TCP拥塞窗口大小来推断消息长度，可在不需要中间人窃听的情况下实施CRIME和BREACH攻击，详见[Blackhat 2016上的HEIST论文](https://www.blackhat.com/docs/us-16/materials/us-16-VanGoethem-HEIST-HTTP-Encrypted-Information-Can-Be-Stolen-Through-TCP-Windows-wp.pdf)。

防御对策：

- Chrome已经在ClientHello中禁止压缩
- TLS 1.2中禁用压缩（压缩方法标识为`null`）
- 禁用压缩！
- 禁止第三方cookie!

### 2.5 重新协商

重新协商（Renegotiation）攻击 ([CVE-2009-3555](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2009-3555))：中间人利用重新协商机制漏洞注入明文。

参考资料：

- [Ray, M., "Authentication Gap in TLS Renegotiation",
November 2009](http://data.proidea.org.pl/confidence/6edycja/materialy/prezentacje/CONFidence2009_frank_breedijk_TLS.pdf)
- [G-SEC TLS & SSLv3 renegotiation vulnerability](http://www.g-sec.lu/practicaltls.pdf)

重新协商漏洞：初始协商与重新协商间没有密码学绑定，重新协商对读写操作透明。

攻击过程：

1. 攻击者与服务器建立TLS连接（0. 可拦截客户端Hello，并插入攻击者Hello）
2. 攻击者发送任意流量A<=>S到服务器
3. 重新协商：客户端与服务器端握手（将第0步客户端Hello放行），攻击者将握手加密发送给服务器，完成握手
	- 重新协商期间可实现基于证书的客户端验证
4. 客户端与服务器通过新建立的安全参数通信，传递流量C<=>S；攻击者并不读取该加密流量

至此，服务器认为初始的流量A<=>S和C<=>S流量都来自与真正客户端。

攻击示意图：
	
```
    Client                   Attacker                   Server
    ------                   -------                    ------
     --------0. ClientHello ---->
                                <--------1. Handshake -------->
                                <==== 2. Initial Traffic =====>
    <--------------------- 3. Handshake ======================>
    <================== 4. Client Traffic ====================>
```

攻击示例：攻击者以自己发出的“支付账号和金额”以及受害用户发出的“cookie”一起拼凑一个支付请求，来盗取受害者账户。
```
A<=>S:

GET /ebanking/paymemoney.cgi?acc=LU00000000000000?amount=1000\n
Ignore-what-comes-now:   <--- without '\n'

C<=>S:

GET /ebanking\nCookie: AS21389:6812HSADI:3991238\n

The request to the server:

GET /ebanking/paymemoney.cgi?acc=LU00000000000000?amount=1000\n
Ignore-what-comes-now: GET /ebanking\n
Cookie: AS21389:6812HSADI:3991238\n

```

对策：[RFC5746: Transport Layer Security (TLS) Renegotiation Indication Extension](https://tools.ietf.org/html/rfc5746)中针对重新协商攻击定义了一个TLS扩展（Renegotiation Indication），强制标明重新协商，通过交换Finished消息中验证信息来将重新协商和TLS连接进行密码学绑定。

### 2.6 三重握手

参考资料：[Triple Handshakes and Cookie Cutters: Breaking and Fixing Authentication over TLS (IEEE S&P 2016)](https://www.mitls.org/downloads/tlsauth.pdf)

三重握手(Triple Handshake) ([CVE-2014-1295](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1295))：攻击者（A）分别与客户端（C）和服务器（S）握手，协商出同一个主密钥；之后令客户端（C）和服务器（S）之间重新协商（renegotiation）或继续（resumption）会话来握手。可攻破重新协商，TLS Exporter [RFC5705](https://tools.ietf.org/html/rfc5705)和"tls-unique" [RFC5929](https://tools.ietf.org/html/rfc5929)。

TLS中漏洞：

- RSA握手中，pms由C用A的公钥加密，A再以客户端身份将pms发送给S；A用相同的客户端随机数（cr），服务器随机数（sr），以及会话ID（sid），令A与C和A与S的两个握手中具有相同的主密钥（ms），ID和密钥。这被称为未知密钥共享（unkown key-share（UKS））攻击。
- DHE握手，A在选择DH群参数时，选择一个非质数群来完全控制pms，从而实现UKS攻击。
- 会话继续在一个新连接上使用简化握手（abbreviated handshake），只验证C和S共享的ms，密码套件和sid，而不重新验证C和S的身份。
- 重新协商中，C和S证书可以更换。（这在当前主要TLS实现中被允许，但没有如何处理证书更换的权威指南）

攻击分3步：

第1步，C连接恶意网站A，A连接S，完成两次握手，实现UKS。攻击RSA握手示意图如下：

```
    Client                                    Attacker                                      Server
    ------                                     -------                                      ------
      |-----ClientHello(cr, [RSA, DH]...)-------->|                                            |
      |                                           | --------ClientHello(cr, [RSA]...) -------->|
      |<------------------------------------------|---ServerHello(sr, sid, RSA, ENC_ALG)...)---|
      |                                           |<--ServerCertificate(cert_S, pk_S)----------|
      |<-----ServerCertificate(cert_A, pk_A)------|                                            |
      |<------------------------------------------|--------------ServerHelloDone---------------|
      |-----ClientKeyExchange(rsa(pms, pk_A))---->|                                            |
      |                                           |------ClientKeyExchange(rsa(pms, pk_S))---->|
      |---------------ClientCCS-------------------|------------------------------------------->|
      |---ClientFinished(verifydata(log1, ms))--->|                                            |
      |                                           |----ClientFinished(verifydata(log1', ms))-->|
      |<------------------------------------------|------------------ServerCCS-----------------|
      |                                           |<---ServerFinished(verifydata(log2, ms))----|
      |<---ServerFinished(verifydata(log2', ms))--|                                            |
      |                                           |                                            |
 Cache new session:                             Knows:                            Cache new session: 
 sid, ms, anon->cert_A,                     sid, ms, cr, sr                    sid, ms, anon->cert_S
 cr, sr, RSA, ENC_ALG                                                           cr, sr, RSA, ENC_ALG
```

第2步，C重连A并继续之前的会话。A也重连S并继续之前的会话。由于之前会话中参数都相同，A只需简单地转发在C和S间的简化握手消息。在完成简化握手后，两个连接具有相同密钥，同时也具有相同finised消息（verfify_data）。A知道新的连接密钥，可以继续发送数据。示意图如下：

```
    Client                                    Attacker                                      Server
    ------                                     -------                                      ------
  Has session:                                  Knows:                            Cache new session: 
 sid, ms, anon->cert_A,                     sid, ms, cr, sr                     sid, ms, anon->cert_S
 cr, sr, KEX_ALG, ENC_ALG                                                    cr, sr, KEX_ALG, ENC_ALG

      |---------ClientHello(cr', sid)-------------|------------------------------------------->|
      |<------------------------------------------|-----------ServerHello(sr' sid)-------------|
      |<------------------------------------------|------------------ServerCCS-----------------|
      |<------------------------------------------|--ServerFinished(cvd=verifydata(log1, ms))--|
      |---------------ClientCCS-------------------|------------------------------------------->|
      |-ClientFinished(svd=verifydata(log1', ms))-|------------------------------------------->|
      |                                           |                                            |
  new connection:                               Knows:                                   New session: 
 sid, ms, cr', sr', cvd, svd               sid, ms, cr', sr'              sid, ms, cr', sr', cvd, svd
```

第3步，S要求A用客户端认证来重新协商，A转发重新协商请求给C，并转发S和C间所有消息。由于Renegotiation Indication扩展验证数据一致，所以握手会成功完成。C和S重新协商后，A不再知道连接密钥或ms，但之前插入的消息可以作为后续消息的前缀。过程略。

防御对策：

- 对于一个连接上所有证书采用相同的验证策略，可以简单地拒绝重新协商过程中的任何证书改变
- 将ms与完整握手绑定，例如在ms派生方案中包含握手消息哈希值，令ms来隐式认证客户端和服务器身份以及所有会话参数
- 将简化会话继续握手与完全握手绑定，在简化握手中加入一个secure resumption indication扩展，包含创建会话的握手消息哈希值

### 3. CA安全增强

- 多数浏览器相信上百个CA，任何一个CA被攻破，可伪造任何站点证书
- 2011年，两个CA，[DigiNotar](http://en.wikipedia.org/wiki/DigiNotar)和[Comodo](http://en.wikipedia.org/wiki/Comodo_Group)，发布了包括google, yahoo等的假证书
- 2012年，一个CA，[Trustwave](http://www.h-online.com/security/news/item/Trustwave-issued-a-man-in-the-middle-certificate-1429982.html)发布了一个对任意网站都有效的根证书
- 2015年，埃及MSC Holding使用CNNIC签发的中级证书签发gmail假证书，导致Chrome和Firefox移除的CNNIC根证书 [[相关报道]](https://en.wikipedia.org/wiki/China_Internet_Network_Information_Center)


- [Pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning)：PKP(Public-Key Pinning)将信任从根CA公钥转移到其他可信公钥，例如在浏览器内置公钥白名单，或采用首用信任TOFU(trust-on-first-use)机制。- 公证人方案：
	- [Perspectives](https://en.wikipedia.org/wiki/Transport_Layer_Security#Perspectives_Project)通过主动采集证书来扮演一个第三方公证人角色，即在证书权威CA和证书持有者之外提供一个新的证书源，并提供审计功能。
	- [Convergence](https://en.wikipedia.org/wiki/Convergence_(SSL))扩展了Perspectives，对来自客户端的证书请求做了匿名化处理来保护用户隐私。	
	- 这种第三方角色保证了其独立性，但可能由于证书采集问题导致假警报。- 公开日志方案：
	- 由Google提出的[证书透明(certificate transparency)](https://en.wikipedia.org/wiki/Certificate_Transparency)方案引入了一个基于Merkle树的公开、只可追加日志系统，记载CA颁发过的和证书持有者提交的证书，以支撑对CA审计与问责。日志本身也是可审计的，其远景目标是一个证书被客户端所接受当且仅当该证书已被添加到日志中。
	- 在[Sovereign Keys](https://www.eff.org/sovereign-keys)方案中，证书持有者对自己的证书签名并存入公开日志中。- [DANE](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities)（DNS-based Authentication of Named Entities）将多根CA的非层级结构层级化，将多根结构单根化，通过DNSSEC认证域名相应证书，因此，DANE相当于将CA滥用问题转移到DNSSEC滥用问题，权利被集中所带来的好处是攻击面减小，缺点是滥用风险更加突出、危害也更大。

---
