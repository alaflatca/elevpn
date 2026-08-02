# elevpn

언어: 한국어 | [English](./README.en.md)

elevpn은 Go로 만든 작은 TUN-over-UDP VPN 프로토타입입니다.

Linux TUN 인터페이스를 만들고, TUN에서 읽은 IPv4 패킷을 자체 UDP 프로토콜로 감싼 뒤 VPN 서버로 보냅니다. 서버는 IP forwarding과 nftables masquerade를 적용해 클라이언트 트래픽이 서버의 공인 네트워크를 통해 나가도록 처리합니다.

운영용 VPN을 목표로 한 프로젝트는 아닙니다. 목표는 VPN의 핵심 데이터 경로를 직접 구현하면서, TUN, route, NAT, UDP transport가 어떻게 맞물리는지 이해하는 것입니다.

- TUN device 설정
- UDP tunnel transport
- client/server handshake
- peer 등록
- full-tunnel route 변경
- SSH 접속 유지를 위한 자동 bypass route
- nftables masquerade
- graceful cleanup

## 현재 상태

현재 버전은 클라이언트 트래픽을 서버를 통해 외부로 내보낼 수 있습니다.

아래 테스트에서 클라이언트 EC2의 공인 IP는 `43.203.156.141`입니다.

```text
43.203.156.141
```

VPN 서버 EC2의 공인 IP는 `15.165.48.135`입니다.

```text
15.165.48.135
```

클라이언트의 default route를 `tun0`로 변경한 뒤 `api.ipify.org`를 호출하면 서버 공인 IP가 반환됩니다.

```json
{"ip":"15.165.48.135"}
```

## 동작 흐름

클라이언트는 먼저 UDP로 서버에 `ALOHA` 메시지를 보냅니다.

서버는 클라이언트를 peer로 등록하고 tunnel IP를 할당한 뒤, `WELCOME` 메시지로 응답합니다.

```text
client
  -> ALOHA

server
  -> register peer
  -> allocate tunnel IP
  -> WELCOME(peer_id, tunnel_ip, mtu)
```

`handshake`가 끝나면 양쪽은 `DATA` 메시지로 TUN 패킷을 주고받습니다.

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

## Route 정책

클라이언트는 full-tunnel 방식으로 동작합니다. VPN 연결 후 default route를 `tun0`로 변경해 일반 트래픽을 tunnel로 보냅니다.

단, tunnel 자체와 원격 접속이 끊기지 않도록 다음 목적지는 기존 gateway/interface로 bypass합니다.

```text
VPN server endpoint /32
현재 SSH 접속자의 remote IP /32
```

SSH remote IP는 `NETLINK_SOCK_DIAG`/`INET_DIAG`로 커널의 현재 TCP socket 목록을 조회해 찾습니다. `local port 22`의 `ESTABLISHED` 연결을 찾고, 해당 연결의 remote IP를 `/32` route로 추가합니다.

```text
15.165.48.135/32 via 172.31.48.1 dev ens5
220.76.48.11/32 via 172.31.48.1 dev ens5
default dev tun0
```

이 방식으로 `sudo` 실행 시 `SSH_CLIENT` 같은 환경변수가 전달되지 않아도 SSH 접속을 유지할 수 있습니다.

## 프로토콜

모든 UDP 패킷은 작은 고정 header를 사용합니다.

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

실제 네트워크 인터페이스 MTU가 1500일 때, VPN이 추가하는 header 크기를 고려해 TUN MTU를 1460으로 낮춥니다.

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
2026/07/30 08:49:53 [route] detected ssh bypass cidrs=[220.76.48.11/32]
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
default dev tun0 proto static scope link
15.165.48.135 via 172.31.48.1 dev ens5 proto static
172.31.0.2 via 172.31.48.1 dev ens5 proto dhcp src 172.31.50.196 metric 512
172.31.48.0/20 dev ens5 proto kernel scope link src 172.31.50.196 metric 512
172.31.48.1 dev ens5 proto dhcp scope link src 172.31.50.196 metric 512
220.76.48.11 via 172.31.48.1 dev ens5 proto static
```

VPN 서버 endpoint와 SSH 접속자의 remote IP는 tunnel 밖으로 유지합니다.

```text
15.165.48.135 via 172.31.48.1 dev ens5 proto static
220.76.48.11 via 172.31.48.1 dev ens5 proto static
```

이 예외 route가 있어야 default route가 `tun0`를 사용하더라도 UDP tunnel과 SSH 접속이 유지됩니다.

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

이 nftables rule은 `10.77.0.0/24`에서 나온 패킷이 `ens5`를 통해 외부로 나갈 때, 출발지 주소를 서버 외부 인터페이스 주소로 masquerade합니다.

## 외부 IP 테스트

full-tunnel 적용 후에는 별도 테스트 route 없이 외부 IP를 조회합니다.

```bash
curl -s https://api.ipify.org?format=json
```

결과:

```json
{"ip":"15.165.48.135"}
```

응답 IP가 VPN 서버의 공인 IP라면, 클라이언트 요청이 tunnel을 거쳐 서버에서 외부로 나간 것입니다.

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

- IPv4만 지원
- 암호화 없음
- 인증 없음
- DNS 설정 없음
- 영구 설정 파일 없음
- SSH 자동 bypass는 TCP local port 22 기준

다음 작업:

- 암호화와 인증 추가
- EC2 또는 Linux network namespace 기반 통합 테스트 스크립트 추가
- 부분 실패 상황에서 route rollback 동작 개선
