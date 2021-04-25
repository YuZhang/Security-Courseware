# 网络拓扑测量


## 0. 互联网拓扑测量基础

- 学习一些互联网拓扑测量基础知识，见[幻灯片](supplyments/topology-measurement.pptx)

## 1. 网络互联基础设施测量  [mapping_peering_interconnections_conext.pdf](../../../../Downloads/mapping_peering_interconnections_conext.pdf) 

- 参考文献：[Mapping Peering Interconnections to a Facility, CoNEXT 2015. (The best paper)](https://www.caida.org/publications/papers/2015/mapping_peering_interconnections/mapping_peering_interconnections.pdf) [[Slides]](http://www.caida.org/publications/presentations/2015/mapping_peering_interconnections_conext/mapping_peering_interconnections_conext.pdf)[[本地]](supplyments/mapping_peering_interconnections_conext.pdf)

- 互联网——一个网络的网络，每个网络称为一个自治域(AS)
- AS间互联关系：
	- Provider-Customer：前者为后者提供transit服务
	- Peer-Peer：两者彼此传递自己和costomer的流量
- AS间互联设施：
	- Interconnection/colocation Facility（IF，互联机房）：支持网络接入和互联的机房，为用户提供管理、网络、电力、空调、防火等服务。
		- 许多大公司，例如Equinix、Telehouse、Interxion在全球运营这类设施。
		- 大多数IF是ISP中立的，但也有一些是ISP运营的，例如Level3。
		- 在一个大城市中，一个公司会运营多个IF，这些机房互联。
	- Internet eXchange Point（IXP，互联网交换点）：IXP是通过switch fabric构造的一个Layer-2以太交换机构成的设施。
		- 每个IXP有多个高端交换机，称为核心交换机（core switch）。
		- 与IXP同一城市的多个IF上部署接入交换机（acess switch），并与核心交换机互联。
		- 接入交换机有时与核心交换机通过回程交换机（backhaul switch）互联。
- AS间互联方式：
	- Private Peering with Cross-connect（CC，跨站点连接）：在不同地点的两个网络通过电路交换网络，例如光纤，彼此互联。
		- 大型IF上可能有上千条CC，例如Equinix报告了在其全球的IF上有161.7K条CC（2015 Q2）。
		- IXP可以从IF批发购买大量CC，然后IXP成员从IXP购买CC。例如，DE-CIX在法兰克福有900个CC（2015年2月）。
	- Public Peering（公开互联）：在IXP内的两个成员公开互联。
		- 两个AS直接建立BGP会话实现双边互联，或多个AS通过RS（Route Server）实现多边互联。
		- IXP通常拥有一个ASN和一个IP前缀。
		- 多边互联时，每个AS与IXP的RS建立BGP会话。
		- IXP优势在于，租用一个端口，可以与大量AS互联。
	- Private Interconnects over IXP（通过IXP来私有互联）：也称作tethering（共享）或IXP metro VLAN。 
		- Tethering：通过IXP内VLAN（例如，IEEE 802.1Q）实现的点对点虚拟私有专线。
	- Remote Peering（远程互联）：一些IXP允许成员从任何地点接入。
		- 可通过Ethernet-over-MPLS实现到IXP的连接。
		- 2013年，AMS-IX的近20%成员通过此方式接入。
- 收集AS、机房与IXP映射信息
	- AS与机房映射信息：PeeringDB、AS的NOC网页
	- IXP与机房映射信息：IXP网站、PeeringDB、PCH、Euro-IX、Af-IX、LAC-IX和APIX
	- 2015年，87个国家中263个城市中368个IXP，95个国家中684个城市中1694个机房
- traceroute测量
	- 测量系统：RIPE Atlas(6385)、Looking Glasses(1877)、iPlane(147)、CAIDA Ark(107)
	- 别名解析（Alias resolution），基于主动探测，与分析（MIDAR）
	- IP2AS mapping（基于BGP路由数据，但包含错误），获得三级路径：IP级、路由器级、AS级
- Constrained Facility Search (CFS)算法
	1. 识别公开和私有连接
		- 若`IP_A, IP_e, IP_B`，其中`IP_e`为IXP地址，则为公开连接`A, B`
		- 若`IP_A, IP_B`，则为私有连接
	2. 初始机房搜索（确定一个AS的IP地址所在机房） ，对于公开连接`IP_A, IP_IXP, IP_B`
		1. Resolved interface: AS A和IXP只有一个公共的机房，则`IP_A`位于该机房
		2. Unresolved local interface：AS A和IXP有多个共同的机房，则`IP_A`位于这些机房之一
		3. AS A和IXP没有公共机房：
			1. Unresolved remote interface: AS A与IXP远程连接 （根据延迟来判断） 
			2. Missing data: AS A所在机房数据不完整
		4. 对于私有连接`IP_A, IP_B`，方法类似
	3. 通过别名解析来缩小机房范围：同一台路由器上别名应属于同一机房 
	4. 通过定向traceroute发现更多的（之前未探测的）路径，来进一步缩小机房范围。思路是最小化新连接两端机房的交集。 
- 进一步确定机房
	- 反向搜索：从另一个方向重复之前1-4步
	- 邻近启发式：`IP_A, IP_IXP, IP_B`中`IP_A`的机房已经确定，则`IP_B`所在机房应与之接近
- 下面来通过幻灯片学习

- 其他参考资料：
	- [Anatomy of a Large European IXP, SIGCOMM 2012.](https://www.cs.rutgers.edu/~badri/552dir/papers/meas/ager2012.pdf) [[slides]](http://www.caida.org/workshops/wie/1412/slides/wie2014_icastro.pdf)
	- [Remote Peering: More Peering without Internet Flattening. CoNEXT 2015](http://conferences2.sigcomm.org/co-next/2014/CoNEXT_papers/p185.pdf) [[slides]](http://www.caida.org/workshops/wie/1412/slides/wie2014_icastro.pdf)
	- [Layer 1-Informed Internet Topology Measurement. IMC'14.]()



## 1. 检测互联基础设施停运

参考文献：[Detecting Peering Infrastructure Outages in the Wild, ACM SIGCOMM 2017. (with slides)](http://www.caida.org/publications/presentations/2017/detecting_peering_infrastructure_outages_ucla/)[[本地]](supplyments/detecting_peering_infrastructure_outages_ucla.pdf)

摘要：互联(peering)基础设施，即主机托管设施(colocation)和互联网交换点(IXP)，位于每个主要城市，拥有数百个网络成员，并支持全球数十万的网络互联。这些基础设施的配置和管理都很好，但是由于电源故障、人为错误，攻击和自然灾害等原因，可能会造成中断。然而，对于这些关键基础设施的停运频率和影响知之甚少。开发了一种新颖轻量级的方法来检测互联基础设施停运。我们的方法论依赖于一个观察：BGP路由更新中声明的BGP团体属性是一个极好但尚未开发的信息源，使我们能够很准确地定位停运位置。我们建立并运营一套系统，可以在建筑物级别定位基础设施停运的中心，并近乎实时地追踪网络的反应。与过去几年公开报道的相比，我们的分析发现了四倍的停运。这种中断对远程网络和互联基础设施产生了重大影响。我们的研究提供了一个互联网在压力下的行为的独特视角，这种压力往往没有报道。



----

