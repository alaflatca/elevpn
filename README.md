# elevpn

언어: 한국어 | [English](./README.en.md)

elevpn은 Go로 만든 작은 TUN-over-UDP VPN 프로토타입입니다.

Linux TUN 인터페이스를 만들고, TUN에서 읽은 IPv4 패킷을 자체 UDP 프로토콜로 감싼 뒤 VPN 서버로 보냅니다. 서버는 IP forwarding과 nftables masquerade를 적용해 클라이언트 트래픽이 서버의 공인 네트워크를 통해 나가도록 처리합니다.

운영용 VPN을 목표로 한 프로젝트는 아닙니다. 목표는 VPN의 핵심 데이터 경로를 직접 구현하면서, TUN, route, NAT, UDP transport가 어떻게 맞물리는지 이해하는 것입니다.

- TUN device 설정
- UDP tunnel transport
- PSK/HMAC-SHA256 기반 packet 인증과 무결성 검증
- client/server handshake
- peer 등록
- full-tunnel route 변경
- SSH 접속 유지를 위한 자동 bypass route
- nftables masquerade
- graceful cleanup

## 현재 상태

현재 버전은 클라이언트 트래픽을 서버를 통해 외부로 내보낼 수 있습니다.

아래 테스트에서 클라이언트 EC2의 공인 IP는 `3.35.200.113`입니다.

```text
3.35.200.113
```

VPN 서버 EC2의 공인 IP는 `54.116.44.5`입니다.

```text
54.116.44.5
```

클라이언트의 default route를 `tun0`로 변경한 뒤 `api.ipify.org`를 호출하면 서버 공인 IP가 반환됩니다.

```json
{"ip":"54.116.44.5"}
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

전체 데이터 흐름은 아래와 같습니다.

```text
┌──────────────── Client ────────────────┐
│                                         │
│  App traffic                            │
│      │                                  │
│      ▼                                  │
│  Kernel route                           │
│      │                                  │
│      ▼                                  │
│  tun0                                   │
│      │ raw IP packet                    │
│      ▼                                  │
│  elevpn client                          │
│      │ EncodePacket + HMAC tag          │
│      ▼                                  │
└──────┼──────────────────────────────────┘
       │ UDP
       ▼
┌──────────────── Server ────────────────┐
│                                         │
│  elevpn server                          │
│      │ Verify HMAC + DecodePacket       │
│      ▼                                  │
│  tun0                                   │
│      │ raw IP packet                    │
│      ▼                                  │
│  IP forwarding                          │
│      ▼                                  │
│  nftables masquerade                    │
│      ▼                                  │
│  Internet                               │
│                                         │
└─────────────────────────────────────────┘
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
54.116.44.5/32 via 172.31.48.1 dev ens5
221.167.251.145/32 via 172.31.48.1 dev ens5
default dev tun0
```

이 방식으로 `sudo` 실행 시 `SSH_CLIENT` 같은 환경변수가 전달되지 않아도 SSH 접속을 유지할 수 있습니다.

## 프로토콜

UDP로 전송되는 elevpn packet은 작은 고정 header와 가변 payload, HMAC tag로 구성됩니다.

```text
[message header 12 bytes][payload variable][hmac tag 32 bytes]
```

`message header`:

```text
0      version
1      message type
2      flags
3      reserved
4:12   peer ID, uint64, big-endian
```

HMAC tag는 `message header + payload` 전체를 대상으로 계산합니다. 수신 측은 같은 PSK로 HMAC-SHA256 tag를 다시 계산하고, 받은 tag와 비교해 packet 인증과 무결성을 확인합니다.

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

초기 구현에서는 실제 네트워크 인터페이스 MTU가 1500일 때, VPN이 추가하는 header 크기를 고려해 TUN MTU를 1460으로 낮췄습니다.

HMAC tag가 추가되면서 실제 UDP packet 뒤에는 32 bytes가 더 붙습니다. 현재는 기능 검증 단계이며, 다음 단계에서 `MaxPayloadSize`와 TUN MTU를 outer packet 크기 기준으로 다시 조정할 예정입니다.

## 빌드

Linux x86_64용 빌드:

```bash
GOOS=linux GOARCH=amd64 go build -o bin/elevpn .
```

프로그램은 TUN device 생성, route 변경, IP forwarding 설정, nftables rule 적용을 수행하므로 권한이 필요합니다. 아래 예시는 `sudo`로 실행합니다.

## 실행

서버:

```bash
sudo ./elevpn server --psk test-secret
```

클라이언트:

```bash
sudo ./elevpn client --server-endpoint=54.116.44.5:9010 --psk test-secret
```

`--psk`는 서버와 클라이언트가 같은 값을 사용해야 합니다. 기본값 `test-secret`은 테스트 편의를 위한 값입니다.

## 테스트 실행 로그

서버 로그:

```text
[ec2-user@ip-172-31-52-136 ~]$ sudo ./elevpn server --psk test-secret
2026/08/03 13:12:29 [init] listen=0.0.0.0:9010 tun-name=tun0 vpn-network-cidr=10.77.0.0/24
2026/08/03 13:12:29 [route] default interface=ens5 index=2 gateway="172.31.48.1"
2026/08/03 13:12:44 [handshake] received ALOHA from 3.35.200.113:47624
2026/08/03 13:12:44 [handshake] registered peer id=1 tunnel_ip=10.77.0.2 mtu=1460
2026/08/03 13:12:44 [handshake] sent WELCOME peer_id=1 tunnel_ip=10.77.0.2 mtu=1460
2026/08/03 13:12:54 [keepalive] peer_id=1 last_seen updated
```

클라이언트 로그:

```text
[ec2-user@ip-172-31-50-229 ~]$ sudo ./elevpn client --server-endpoint=54.116.44.5:9010 --psk test-secret
2026/08/03 13:12:44 [init] listen=:0 endpoint=54.116.44.5:9010 tunName=tun0
2026/08/03 13:12:44 [handshake] sent ALOHA to 54.116.44.5:9010
2026/08/03 13:12:44 [handshake] received WELCOME peer_id=1 tunnel_ip=10.77.0.2 mtu=1460
2026/08/03 13:12:44 [route] default interface=ens5 index=2 gateway="172.31.48.1"
2026/08/03 13:12:44 [route] detected ssh bypass cidrs=[54.116.44.5/32 221.167.251.145/32]
```

## 인터페이스 상태

서버 TUN 인터페이스:

```text
[ec2-user@ip-172-31-52-136 ~]$ ip addr show tun0
11: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1460 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.77.0.1/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::1b5c:be8e:70f9:dbed/64 scope link stable-privacy proto kernel_ll
       valid_lft forever preferred_lft forever
```

클라이언트 TUN 인터페이스:

```text
[ec2-user@ip-172-31-50-229 ~]$ ip addr show tun0
8: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1460 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.77.0.2/32 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::4591:5d54:ec2a:9ddc/64 scope link stable-privacy proto kernel_ll
       valid_lft forever preferred_lft forever
```

## 라우트 상태

서버 라우트:

```text
[ec2-user@ip-172-31-52-136 ~]$ ip route show
default via 172.31.48.1 dev ens5 proto dhcp src 172.31.52.136 metric 512
10.77.0.0/24 dev tun0 proto kernel scope link src 10.77.0.1
172.31.0.2 via 172.31.48.1 dev ens5 proto dhcp src 172.31.52.136 metric 512
172.31.48.0/20 dev ens5 proto kernel scope link src 172.31.52.136 metric 512
172.31.48.1 dev ens5 proto dhcp scope link src 172.31.52.136 metric 512
```

클라이언트 라우트:

```text
[ec2-user@ip-172-31-50-229 ~]$ ip route show
default dev tun0 proto static scope link
default via 172.31.48.1 dev ens5 proto dhcp src 172.31.50.229 metric 512
54.116.44.5 via 172.31.48.1 dev ens5 proto static
172.31.0.2 via 172.31.48.1 dev ens5 proto dhcp src 172.31.50.229 metric 512
172.31.48.0/20 dev ens5 proto kernel scope link src 172.31.50.229 metric 512
172.31.48.1 dev ens5 proto dhcp scope link src 172.31.50.229 metric 512
221.167.251.145 via 172.31.48.1 dev ens5 proto static
```

VPN 서버 endpoint와 SSH 접속자의 remote IP는 tunnel 밖으로 유지합니다.

```text
54.116.44.5 via 172.31.48.1 dev ens5 proto static
221.167.251.145 via 172.31.48.1 dev ens5 proto static
```

이 예외 route가 있어야 default route가 `tun0`를 사용하더라도 UDP tunnel과 SSH 접속이 유지됩니다.

## NAT Rule

서버는 VPN network에 대해 nftables masquerade rule을 생성합니다.

```text
[ec2-user@ip-172-31-52-136 ~]$ sudo nft list ruleset
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
{"ip":"54.116.44.5"}
```

응답 IP가 VPN 서버의 공인 IP라면, 클라이언트 요청이 tunnel을 거쳐 서버에서 외부로 나간 것입니다.

## Cleanup

클라이언트 종료:

```text
^C2026/08/03 13:18:00 [Route] elapsed time: 509.09µs
2026/08/03 13:18:00 [tun0] tun interface close
2026/08/03 13:18:00 [tun0] elapsed time: 59.091121ms
2026/08/03 13:18:00 uptime: 5m16.476614408s
```

서버 종료:

```text
^C2026/08/03 13:18:15 runTunnel end (context.Canceled)
2026/08/03 13:18:15 [Masquerade (vpnnat)] elapsed time: 16.14482ms
2026/08/03 13:18:15 [IPForward] elapsed time: 152.742µs
2026/08/03 13:18:15 [tun0] tun interface close
2026/08/03 13:18:15 [tun0] elapsed time: 39.847988ms
2026/08/03 13:18:15 uptime: 5m46.301056623s
```

## 메모

현재 제한사항:

- IPv4만 지원
- payload 암호화 없음
- replay attack 방지 없음
- DNS 설정 없음
- 영구 설정 파일 없음
- PSK 배포/교체 구조 없음
- SSH 자동 bypass는 TCP local port 22 기준

다음 작업:

- sequence number 또는 nonce 추가
- AEAD 기반 payload 암호화 검토
- EC2 또는 Linux network namespace 기반 통합 테스트 스크립트 추가
- 부분 실패 상황에서 route rollback 동작 개선
