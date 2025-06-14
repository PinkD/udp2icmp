# udp2icmp

## 功能

使用 bpf 实现了以下功能：

- 客户端将发送到指定地址的 udp 数据包加上 icmp echo request 的 header ，伪造为 icmp 数据包
- 服务端收到 icmp 数据包后，移除 icmp header ，并将对应 udp 数据包发送到本机对应的 udp 端口
- 服务端向客户端回复数据包时，也需要按照同样的规则加上 icmp header ，但是返回的 icmp 数据包需要是 echo reply
- 为了尽可能伪装成 icmp 数据包，客户端和服务端都记录了对应地址的 icmp 序列号，每次发送时均加一

计划实现的功能：

- 对 icmp body 进行加密，防止被检测到

## 用法

### 编译

```bash
# archlinux
cd pack
makepkg

# other linux
make
```

### 运行

```bash
# modify args
vim /etc/default/udp2icmp
# start service
systemctl start udp2icmp.service
```

详细参数：

```text
Usage: udp2icmp [options]

Description:
    Wrap udp packet with icmp header using bpf.

Options:
  -h, --help                   Print help message.
  -t, --target <ip:port>       Target address. Set multiple targets with multiple --target options.
                               NOTE: This option implies client mode.
  -i, --interface <interface>  Interface to attach XDP program.(Required)
  -m, --mode <mode>            Mode to attach XDP program.(native/skb, default: native)
  -l, --log-level <level>      Log level.(trace/debug/info/warn/error/none, default: info)
```

服务端只需要指定 `--interface` ，客户端还需要用 `--target` 指定服务端，可以多次传入指定多个服务端

## 已知问题

如果服务端收到的 icmp 包的 checksum 字段不正确，需要关闭客户端的 checksum offload 功能，命令如下：

```bash
ethtool -K eth0 tx-checksumming off
```

该问题目前没有找到根本原因和代码层面的解决方案。从现象来看，应该是 udp 的 checksum 的位置(offset)被记录用于 checksum offload ，而 `bpf_skb_adjust_room` 函数未能正确重置 skb 中的该字段，导致网卡仍然尝试用旧的 udp checksum 位置计算 checksum ，并修改了该字段，导致 icmp 包的数据部分发生变化，校验和也就发生变化了

## 特别感谢

本项目部分思路受 [mimic](https://github.com/hack3ric/mimic) 启发

## License

```
    Wrap udp packet with icmp header using bpf

    Copyright (C) 2025  PinkD

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
```
