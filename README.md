# 简介

使用 bpf 实现以下功能：

- 客户端将发送到指定地址的 udp 数据包加上 icmp echo request 的 header ，伪造为 icmp 数据包
- 服务端收到 icmp 数据包后，移除 icmp header ，并将对应 udp 数据包发送到本机对应的 udp 端口
- 服务端向客户端回复数据包时，也需要按照同样的规则加上 icmp header ，但是返回的 icmp 数据包需要是 echo reply

其他要求：

- 为了尽可能伪装成 icmp 数据包，客户端和服务端都需要记录对应地址的 icmp 序列号，每次发送时均加一
- TODO：对 icmp body 进行加密，防止被识别
