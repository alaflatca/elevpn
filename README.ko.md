# elevpn

언어: [English](./README.md) | 한국어

elevpn은 Go로 작성한 작은 TUN-over-UDP VPN 프로토타입입니다.

Linux TUN 인터페이스를 만들고, TUN에서 읽은 IPv4 패킷을 자체 UDP 프로토콜로 감싼 뒤 VPN 서버로 보냅니다. 서버는 IP forwarding과 nftables masquerade를 사용해서 클라이언트 트래픽이 서버의 공인 네트워크를 통해 나가도록 처리합니다.

이 프로젝트는 production VPN이 아닙니다. 목적은 VPN의 핵심 데이터 경로를 직접 구현하고 이해하는 것입니다.

- TUN device 설정
- UDP tunnel transport
- client/server handshake
- peer 등록
- route 변경
- nftables masquerade
- graceful cleanup

## 현재 상태

현재 MVP는 클라이언트 트래픽을 서버를 통해 외부로 내보낼 수 있습니다.

아래 테스트에서 클라이언트 EC2의 공인 IP는 다음과 같습니다.

```text
43.203.156.141
```

VPN 서버 EC2의 공인 IP는 다음과 같습니다.

```text
15.165.48.135
```

트래픽을 `tun0`로 보낸 뒤 `api.ipify.org`를 호출하면 서버 공인 IP가 반환됩니다.

```json
{"ip":"15.165.48.135"}
```

## 동작 흐름

클라이언트는 UDP로 서버에 `ALOHA` 메시지를 보냅니다.

서버는 클라이언트를 peer로 등록하고, tunnel IP를 할당한 뒤 `WELCOME` 메시지를 응답합니다.

```text
client
  -> ALOHA

server
  -> register peer
  -> allocate tunnel IP
  -> WELCOME(peer_id, tunnel_ip, mtu)
```

handshake 이후에는 양쪽이 `DATA` 메시지로 TUN 패킷을 주고받습니다.

```text
client application traffic
  -> client tun0
  -> elevpn DATA packet
  -> UDP
  -> server
  -> server tun0
  -> IP forwarding
  -> nftables masquerade
  -> internet
```

응답 패킷은 서버 TUN 인터페이스와 peer table을 통해 다시 클라이언트로 돌아갑니다.

```text
internet response
  -> server
  -> server tun0
  -> destination tunnel IP lookup
  -> peer UDP address
  -> client
  -> client tun0
```

## 프로토콜

모든 UDP packet은 작은 고정 header를 사용합니다.

```text
0      version
1      message type
2      flags
3      reserved
4:12   peer ID, uint64, big-endian
12:    payload
```

message type:

```text
1  ALOHA
2  WELCOME
3  DATA
4  KEEPALIVE
```

`WELCOME` payload:

```text
0:4  client tunnel IPv4
4:6  tunnel MTU, uint16, big-endian
```

`DATA` payload:

```text
TUN interface에서 읽은 raw IPv4 packet
```

현재 tunnel MTU는 `1460`입니다.

```text
outer IPv4 header   20 bytes
UDP header           8 bytes
elevpn header       12 bytes
----------------------------
overhead            40 bytes

1500 - 40 = 1460
```

실제 네트워크 인터페이스 MTU가 1500일 때, VPN이 추가하는 header 크기를 고려해서 TUN MTU를 1460으로 낮춥니다.

## 빌드

Linux x86_64용 빌드:

```bash
GOOS=linux GOARCH=amd64 go build -o bin/elevpn .
```

프로그램은 TUN device 생성, route 변경, IP forwarding 설정, nftables rule 적용을 수행하므로 권한이 필요합니다. 아래 예시는 `sudo`로 실행합니다.

## 실행

서버:

```bash
sudo ./elevpn server
```

클라이언트:

```bash
sudo ./elevpn client --server-endpoint=15.165.48.135:9010
```

## 테스트 실행 로그

서버 로그:

```text
[ec2-user@ip-172-31-60-244 ~]$ sudo ./elevpn server
2026/07/30 08:49:48 [init] listen=0.0.0.0:9010 tun-name=tun0 vpn-network-cidr=10.77.0.0/24
2026/07/30 08:49:48 [route] default interface=ens5 index=2 gateway="172.31.48.1"
2026/07/30 08:49:53 [handshake] received ALOHA from 43.203.156.141:48088
2026/07/30 08:49:53 [handshake] registered peer id=1 tunnel_ip=10.77.0.2 mtu=1460
2026/07/30 08:49:53 [handshake] sent WELCOME peer_id=1 tunnel_ip=10.77.0.2 mtu=1460
```

클라이언트 로그:

```text
[ec2-user@ip-172-31-50-196 ~]$ sudo ./elevpn client --server-endpoint=15.165.48.135:9010
2026/07/30 08:49:53 [init] listen=:0 endpoint=15.165.48.135:9010 tunName=tun0
2026/07/30 08:49:53 [handshake] sent ALOHA to 15.165.48.135:9010
2026/07/30 08:49:53 [handshake] received WELCOME peer_id=1 tunnel_ip=10.77.0.2 mtu=1460
2026/07/30 08:49:53 [route] default interface=ens5 index=2 gateway="172.31.48.1"
```

## 인터페이스 상태

서버 TUN 인터페이스:

```text
[ec2-user@ip-172-31-60-244 ~]$ ip addr show tun0
16: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1460 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.77.0.1/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::f0ea:faed:93cc:b11f/64 scope link stable-privacy proto kernel_ll
       valid_lft forever preferred_lft forever
```

클라이언트 TUN 인터페이스:

```text
[ec2-user@ip-172-31-50-196 ~]$ ip addr show tun0
14: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1460 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.77.0.2/32 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::f0e7:d98e:53e8:6e3c/64 scope link stable-privacy proto kernel_ll
       valid_lft forever preferred_lft forever
```

## 라우트 상태

서버 라우트:

```text
[ec2-user@ip-172-31-60-244 ~]$ ip route show
default via 172.31.48.1 dev ens5 proto dhcp src 172.31.60.244 metric 512
10.77.0.0/24 dev tun0 proto kernel scope link src 10.77.0.1
172.31.0.2 via 172.31.48.1 dev ens5 proto dhcp src 172.31.60.244 metric 512
172.31.48.0/20 dev ens5 proto kernel scope link src 172.31.60.244 metric 512
172.31.48.1 dev ens5 proto dhcp scope link src 172.31.60.244 metric 512
```

클라이언트 라우트:

```text
[ec2-user@ip-172-31-50-196 ~]$ ip route show
default via 172.31.48.1 dev ens5 proto dhcp src 172.31.50.196 metric 512
15.165.48.135 via 172.31.48.1 dev ens5 proto static
104.26.13.205 dev tun0 scope link
172.31.0.2 via 172.31.48.1 dev ens5 proto dhcp src 172.31.50.196 metric 512
172.31.48.0/20 dev ens5 proto kernel scope link src 172.31.50.196 metric 512
172.31.48.1 dev ens5 proto dhcp scope link src 172.31.50.196 metric 512
```

VPN 서버 endpoint로 가는 route는 tunnel 밖으로 유지합니다.

```text
15.165.48.135 via 172.31.48.1 dev ens5 proto static
```

이 예외 route가 있어야 default route나 테스트 route가 `tun0`를 사용하더라도 UDP tunnel 자체가 끊기지 않습니다.

## NAT Rule

서버는 VPN network에 대해 nftables masquerade rule을 생성합니다.

```text
[ec2-user@ip-172-31-60-244 ~]$ sudo nft list ruleset
table ip vpnnat {
        chain vpn-postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip saddr 10.77.0.0/24 oifname "ens5" masquerade
        }
}
```

이 rule은 `10.77.0.0/24`에서 나온 패킷이 `ens5`를 통해 외부로 나갈 때 서버 외부 인터페이스 주소로 masquerade되도록 합니다.

## 외부 IP 테스트

테스트에서는 특정 외부 IP 하나만 `tun0`로 보냈습니다.

```bash
sudo ip route add 104.26.13.205/32 dev tun0
```

그리고 `api.ipify.org` 요청이 해당 IP로 가도록 `curl --resolve`를 사용했습니다.

```bash
curl -s --resolve api.ipify.org:443:104.26.13.205 https://api.ipify.org?format=json
```

결과:

```json
{"ip":"15.165.48.135"}
```

응답 IP가 VPN 서버의 공인 IP이므로, 클라이언트 요청이 tunnel을 거쳐 서버에서 외부로 나갔음을 확인할 수 있습니다.

## Cleanup

클라이언트 종료:

```text
Ctrl+C

2026/07/30 09:07:59 Teardown start
2026/07/30 09:07:59 [Route] elapsed time: 451.641µs
2026/07/30 09:07:59 [tun0] tun interface close
2026/07/30 09:07:59 [tun0] elapsed time: 60.231806ms
2026/07/30 09:07:59 Teardown end
2026/07/30 09:07:59 uptime: 18m6.154593862s
```

서버 종료:

```text
Ctrl+C

2026/07/30 09:08:20 runTunnel end (context.Canceled)
2026/07/30 09:08:20 Teardown start
2026/07/30 09:08:20 [Masquerade (vpnnat)] elapsed time: 15.489814ms
2026/07/30 09:08:20 [IPForward] elapsed time: 152.03µs
2026/07/30 09:08:20 [tun0] tun interface close
2026/07/30 09:08:20 [tun0] elapsed time: 79.858228ms
2026/07/30 09:08:20 Teardown end
2026/07/30 09:08:20 uptime: 18m31.852696443s
```

## 메모

현재 제한사항:

- IPv4 only
- encryption 없음
- authentication 없음
- peer lifecycle은 최소 구현 상태
- DNS 설정 없음
- persistent config file 없음

다음 작업:

- encryption과 authentication 추가
- peer expiration과 keepalive 처리
- WELCOME payload encode/decode helper 분리
- EC2 또는 Linux network namespace 기반 통합 테스트 스크립트 추가
- 부분 실패 상황에서 route rollback 동작 개선
