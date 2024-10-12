# Networking and Kubernetes(book)

IP addresses are assigned to network interfaces. A typical interface may have one IPv4 address and one IPv6 address, but multiple addresses can be assigned to the same interface.


 Bridges allow pods, with their individual network interfaces, to interact with the broader network via the node’s network interface.

 ![alt text](images/image-88.png)

 The veth device is a local Ethernet tunnel. Veth devices are created in pairs

  Packets transmitted on one device in the pair are immediately received on the other device. When either device is down, the link state of the pair is down

```sh
NF_IP_PRE_ROUTING(Netfilter hook)

PREROUTING(Iptables chain)

Triggers when a packet arrives from an external system.
```
```sh
NF_IP_LOCAL_IN(Netfilter hook)

INPUT(Iptables chain)

Triggers when a packet’s destination IP address matches this machine.
```

```sh
NF_IP_FORWARD(Netfilter hook)

NAT(Iptables chain)

Triggers for packets where neither source nor destination matches the machine’s IP addresses (in other words, packets that this machine is routing on behalf of other machines).

```
```sh
NF_IP_LOCAL_OUT(Netfilter hook)

OUTPUT(Iptables chain)

Triggers when a packet, originating from the machine, is leaving the machine.
```

```sh
NF_IP_POST_ROUTING(Netfilter hook)

POSTROUTING(Iptables chain)

Triggers when any packet (regardless of origin) is leaving the machine.

```

![alt text](images/image-89.png)


We can infer from our flow diagram that only certain permutations of Netfilter hook calls are possible for any given packet. For example, a packet originating from a local process will always trigger `NF_IP_LOCAL_OUT` hooks and then `NF_IP_POST_ROUTING` hooks. In particular, the flow of Netfilter hooks for a packet depends on two things: if the packet source is the host and if the packet destination is the host. Note that if a process sends a packet destined for the same host, it triggers the `NF_IP_LOCAL_OUT` and then the `NF_IP_POST_ROUTING` hooks before “reentering” the system and triggering the `NF_IP_PRE_ROUTING` and `NF_IP_LOCAL_IN` hooks.


```sh
Packet source	  Packet destination	Hooks (in order)
Local machine     Local machine         NF_IP_LOCAL_OUT, NF_IP_LOCAL_IN

Local machine     External machine      NF_IP_LOCAL_OUT, NF_IP_POST_ROUTING

External machine  Local machine         NF_IP_PRE_ROUTING, NF_IP_LOCAL_IN

External machine   External machine     NF_IP_PRE_ROUTING, NF_IP_FORWARD, NF_IP_POST_ROUTING


#Note that packets from the machine to itself will trigger NF_IP_LOCAL_OUT and NF_IP_POST_ROUTING and then “leave” the network interface. They will “reenter” and be treated like packets from any other source
```

Network address translation (NAT) only impacts local routing decisions in the `NF_IP_PRE_ROUTING` and `NF_IP_LOCAL_OUT `hooks (e.g., the kernel makes no routing decisions after a packet reaches the `NF_IP_LOCAL_IN` hook). We see this reflected in the design of iptables, where source and destination NAT can be performed only in specific hooks/chains.

NAT relies on Conntrack to function. iptables exposes NAT as two types: SNAT (source NAT, where iptables rewrites the source address) and DNAT (destination NAT, where iptables rewrites the destination address).

Conntrack identifies connections by a tuple, composed of source address, source port, destination address, destination port, and L4 protocol. These five pieces of information are the minimal identifiers needed to identify any given L4 connection. All L4 connections have an address and port on each side of the connection; after all, the internet uses addresses for routing, and computers use port numbers for application mapping. The final piece, the L4 protocol, is present because a program will bind to a port in TCP or UDP mode (and binding to one does not preclude binding to the other). Conntrack refers to these connections as flows. A flow contains metadata about the connection and its state.

Conntrack stores flows in a hash table,using the connection tuple as a key

![alt text](images/image-90.png)

```sh
#Conntrack’s max size
cat /proc/sys/net/nf_conntrack_max
65536

#hash table size 
cat /sys/module/nf_conntrack/parameters/hashsize
65536
```

Conntrack entries contain a connection state, which is one of four states.

When Conntrack is active, `conntrack -L` shows all current flows.

```sh
# anatomy of a Conntrack flow,
tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.1
sport=22 dport=49431 src=10.0.0.1 dst=10.0.0.2 sport=49431 dport=22 [ASSURED]
mark=0 use=1

#<protocol> <protocol number> <flow TTL> [flow state>] <source ip> <dest ip> <source port> <dest port> [] <expected return packet>

```
`The expected return packet is of the form <source ip> <dest ip> <source port> <dest port>`

Subnets are specified by the destination and genmask values.

```sh
# route
Kernel IP routing table
Destination    Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0        10.0.0.1        0.0.0.0         UG    303    0        0 eth0
10.0.0.0       0.0.0.0         255.255.255.0   U     303    0        0 eth0

```
Linux prefers to route packets by specificity (how “small” a matching subnet is) and then by weight (“metric” in route output). Given our example, a packet addressed to `10.0.0.1` will always be sent to gateway `0.0.0.0` because that route matches a smaller set of addresses. If we had two routes with the same specificity, then the route with a lower metric wiould be preferred.

10.0.0.0/24 smaller than 0.0.0.0 with only host bits


![alt text](images/image-91.png)
Cilium (a kube-proxy alternative)

a table contains chains, and a chain contains rules.

Chains contain a list of rules. When a packet executes a chain, the rules in the chain are evaluated in order. Chains exist within a table and organize rules according to Netfilter hooks. There are five built-in, top-level chains, each of which corresponds to a Netfilter hook

iptables executes tables in a particular order: `Raw, Mangle, NAT, Filter`

The order of execution is chains, then tables. So, for example, a packet will trigger `Raw PREROUTING`, `Mangle PREROUTING`, `NAT PREROUTING`, and then trigger the Mangle table in either the `INPUT` or `FORWARD` chain (depending on the packet).

iptables chains are a list of rules. When a packet triggers or passes through a chain, each rule is sequentially evaluated, until the packet matches a “terminating target” (such as DROP), or the packet reaches the end of the chain.

![alt text](images/image-92.png)

 DNAT can be performed in `PREROUTING` or `OUTPUT`, and SNAT can be performed in only `INPUT` or `POSTROUTING`.


1. PREROUTING
   1. Raw
   2. Mangle
   3. NAT

2. INPUT
   1. Mangle
   2. NAT
   3. Filter

 when a packet triggers a chain, iptables executes tables within that chain

 `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`

 To display a particular type of DNS record, run `dig <domain> <type>` (or `dig -t <type> <domain>`)

 `dig kubernetes.io TXT`



 From a networking perspective, with one operating system, there is one TCP/IP stack. That single stack creates issues with port conflicts on the host machine

 Each container also has its own network stack

 Image layers in a repository are connected in a parent-child relationship. Each image layer represents changes between itself and the parent layer.

 Repositories can be equivalent to a container image. The important distinction is that repositories are made up of layers and metadata about the image; this is the manifest.

 Docker provides application portability between running on-premise, in the cloud, or in any other data center. Its motto is to build, ship, and run anywhere. 


 In Linux everything is considered a file. This includes hardware devices, processes, directories, regular files, sockets, links, and so on

 IP forwarding is an operating system’s ability to accept incoming network packets on one interface, recognize them for another, and pass them on to that network accordingly. When enabled, IP forwarding allows a Linux machine to receive incoming packets and forward them. A Linux machine acting as an ordinary host would not need to have IP forwarding enabled because it generates and receives IP traffic for its purposes

 Docker uses iptables for network isolation. The container publishes a port to be accessed externally. Containers do not receive a public IPv4 address; they receive a private RFC 1918 address. Services running on a container must be exposed port by port,


 [cni](https://www.sobyte.net/post/2022-10/go-cni/)

 [knet](https://www.sobyte.net/post/2022-10/k8s-net/)

 [container-net-1](https://www.sobyte.net/post/2022-10/container-net-1/)

 [container-net-2](https://www.sobyte.net/post/2022-10/container-net-2/)

 [ipip](https://www.sobyte.net/post/2022-10/ipip/)


[wifi-ethernet-wifi/](https://dx13.co.uk/articles/2022/11/30/wifi-ethernet-wifi/)

the frame payload is transparent to the layer two devices.

Each network interface device must have a unique MAC address within the network, otherwise the network won’t route frames reliably.

 Our devices use ARP to translate IP addresses into MAC addresses. This uses a broadcast frame to ask all devices on a network if they are assigned a particular IP address. Typically a machine on a home network has just one IP address

 `192.168.86.1`


 wifi uses the amplitude and phase of an electromagnetic (radio) wave to transmit bits in the air. 

 n general, to stop each devices waves getting muddled with other devices, at a given moment in time only a single device can transmit or receive data to an access point. This means that devices take turns speaking to their access point


 Unicast: used when a single recipient of a frame is the intended destination

 Group Addresses
 - Broadcast: Used when the Ethernet frame is intended for all the devices that are on the LAN and have a value of `FFFF.FFFF.FFFF`

 - Multicast: Used to allow many but not all of the devices on a LAN to communicate




