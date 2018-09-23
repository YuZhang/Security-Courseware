# IDS（入侵检测系统）

### 哈尔滨工业大学 网络与信息安全 张宇 2018

---

## 1. IDS

[Intrusion detection system](https://en.wikipedia.org/wiki/Intrusion_detection_system)：是一种网络安全设备或应用软件，可以监控网络传输或系统，检查是否有可疑活动或违反政策。发现异常时，发出警报或者采取主动措施。

- IDS最早出现在1980年4月，美国国家安全局的James P. Anderson为美国空军做了一份题为《Computer Security Threat Monitoring and Surveillance》的技术报告，在其中他提出了IDS的概念。
- 防火墙与IDS的不同之处在于，前者通常只监测包头部，后者通常监测整个流量；前者通常不会失效，后者可能会失效；前者通常在通信链路上，后者通常旁路监听
- 与IDS类似的是IPS（入侵阻止系统），其强调发现潜在攻击后阻止攻击；两者的界限并不明显。
- 根据IDS部署的位置，可以分为网络IDS（NIDS），主机IDS（HIDS），分布式IDS（D-IDS）等。
- 从软件系统角度，IDS通常包括如下模块：流量获取与分析，策略配置与知识库，检测与决策引擎，警告生成与响应。
- “The IDS approach to security is based on the assumption that a system will not be secure, but that violations of security policy (intrusions) can be detected by monitoring and analyzing system behavior.” （Forrest 98）
- 最著名的IDS是[Snort](https://en.wikipedia.org/wiki/Snort_(software))，1998年由Martin Roesch创建。2013年被Cisco收购并继续开发，Roesch担任首席安全体系构架师。2009年，Snort进入InfoWorld的开源名人堂。
一个Snort规则的例子：
`alert tcp any any -> 192.168.1.0/24 111 (content:"|00 01 86 a5|"; msg: "mountd access";)`。


### IDS本身也是被攻击目标或者被绕过

例如，攻击者试图让监测器错误地认为是以nice用户登陆

```
                        10 hops            18 hops
“USER” ------------------+----------------->  
TTL=20                   |                  
                         |                  Victim
"nice" ------------------+-----> X         USER:root
TTL=12                   |
                         |
"root" ------------------+----------------->
TTL=20                   |
                     IDS Monitor 

```

### 检测方法：

- 滥用检测（misuse）：根据预先配置的已知攻击模式作为特征来进行检测，也称为Signature-based；Snort和Bro等系统采用此类方法。优点是准确，误报率低，容易跟踪攻击，节省管理时间成本；缺点是容易被“绕过”，需要更新攻击指纹，需要深度包检测，无法应对“未知”攻击；
- 异常检测（abnormal/anomaly）：建立“正常行为”基线，发现偏离了基线的异常事件，用来发现“未知”的攻击；是学术界的研究热点，但很少实际部署，稍后会进一步介绍。优点是可能发现未知攻击，维护成本低，可能越用越准确；缺点是准确率低，可能漏掉攻击，特别是误报率高导致管理时间成本增加；


## 2. Bro

本节学习一个滥用检测NIDS，Bro，最早的入侵检测系统研究之一。Bro: A System for Detecting Network Intruders in Real-Time Vern Paxson [[Slides](supplyments/bro-slides.pdf)]。其设计目标如下：

- 高速大流量监测（在1998年时，100M）
- 不丢包，否则可能漏掉关键消息
- 实时通知
- 机制与政策分离，Mechanism separate from policy
- 可扩展，以应对新攻击
- 避免简单错误，防止安全政策被错误制定
- 监测器可能被攻击（为此提出了一个假设：只有一端会攻击监测器，即另一端时可信的）
- 最后，由于被保护的是基础研究机构，只追求最小化入侵活动，而不追求“无懈可击”的安全

Bro主要包括三个分部：

- libpcap，根据tcpdump过滤器捕包，将数据包流提交给Event Engine
- Event Engine，产生事件，例如，连接已经建立
- Policy Script Interpreter，以政策脚本为输入，输出实时通知或日志

我们通过[[Slides](supplyments/bro-slides.pdf)]来学习一下Bro。

## 3. 异常检测


本节学习一篇关于IDS中采用机器学习方法的异常检测研究论文：Outside the Closed World: On Using Machine Learning for Network Intrusion Detection，IEEE S&P 2010.

这篇论文主要讨论了为什么学术界热衷于采用机器学习方法来进行异常检测，但实际几乎都无法应用。由此，我们来了解一下安全研究和其他计算机应用研究究竟有什么不同。在此之前，我们先了解一下“贝叶斯谬误”。

### 贝叶斯谬误：一个能检测出99%攻击的IDS真的好吗？

- P[T]是攻击概率，即所有网络事件中攻击所占比例
- P[F]是一次事件被IDS标记为攻击的概率
- P[F|T]是IDS供应商声称的准确率，例如P[F|T]=99%，这比当前大多数产品都高
- 考虑一个情况，P[T]=0.0001
- P[F] = P[F|T]xP[T]+P[F|!T]xP[!T] = 0.99x0.0001+0.01x0.9999 = 0.010098
- P[T|F] = P[F|T]xP[T]/P[F] = 0.00x0.0001/0.010098 = 0.0098
- 标记为攻击事件时，实际真正时攻击的概率不到1%
- 因此，降低误报率（false positive）是一个主要问题！

```
| P[T]    | P[F]     | P[F|T]   | P[T|F]   |
|---------|----------|----------|----------|
| 0.1     | 0.38     | 0.65     | 0.171    |
| 0.001   | 0.01098  | 0.99     | 0.090164 |
| 0.1     | 0.108    | 0.99     | 0.911667 |
| 0.00001 | 0.00002  | 0.99999  | 0.5      |
```

下面我们通过一个[[Slides]](supplyments/anomaly.pdf)来学习这篇论文。

----





