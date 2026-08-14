# elevpn

언어: 한국어 | [English](./README.en.md)

elevpn은 Go로 만든 작은 TUN-over-UDP VPN 프로토타입입니다.

Linux TUN 인터페이스를 만들고, TUN에서 읽은 IPv4 패킷을 자체 UDP 프로토콜로 감싼 뒤 VPN 서버로 보냅니다. 서버는 IP forwarding과 nftables masquerade를 적용해 클라이언트 트래픽이 서버의 공인 네트워크를 통해 나가도록 처리합니다.

운영용 VPN을 목표로 한 프로젝트는 아닙니다. 목표는 VPN의 핵심 데이터 경로를 직접 구현하면서, TUN, route, NAT, UDP transport가 어떻게 맞물리는지 이해하는 것입니다.

- TUN device 설정
- UDP tunnel transport
- PSK에서 파생한 AES-GCM key 기반 packet 암호화와 무결성 검증
- `ALOHA`/`WELCOME` client/server handshake
- peer 등록, tunnel IP 할당, keepalive와 만료 처리
- sequence number 기반 replay packet 차단
- full-tunnel route 변경
- SSH 접속 유지를 위한 자동 bypass route
- nftables masquerade
- graceful cleanup

## 현재 상태

마지막으로 검증한 안정 버전은 클라이언트 트래픽을 서버를 통해 외부로 내보낼 수 있습니다. 현재 작업 브랜치에서는 기존 PSK/HMAC packet 인증을 AES-GCM 기반 AEAD 암호화로 교체하고 있습니다.

현재까지 sequence number, client/server random, handshake key와 peer별 key 파생, ALOHA 인증, DATA·KEEPALIVE 암복호화가 코드에 반영됐습니다. WELCOME packet의 최종 key/nonce 규격, TUN MTU 재계산, EC2 통합 테스트가 남아 있으므로 AEAD 적용은 아직 완료 상태가 아닙니다.

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

클라이언트는 handshake마다 `clientRandom`을 생성하고, PSK와 `clientRandom`에서 파생한 handshake key로 `ALOHA`를 인증해 서버로 보냅니다.

서버는 ALOHA를 검증한 뒤 클라이언트를 peer로 등록하고 tunnel IP와 `serverRandom`을 할당해 `WELCOME`으로 응답합니다. 양쪽은 `peer ID + clientRandom + serverRandom`에서 같은 peer key를 만들고 이후 DATA와 KEEPALIVE에 사용합니다.

```text
client
  -> generate clientRandom
  -> ALOHA(sequence=1, clientRandom)

server
  -> authenticate ALOHA
  -> register peer
  -> allocate tunnel IP
  -> generate serverRandom
  -> WELCOME(peer_id, tunnel_ip, mtu, serverRandom)

client/server
  -> derive peer key
  -> exchange encrypted DATA and KEEPALIVE packets
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
│      │ AES-GCM encrypt + authenticate   │
│      ▼                                  │
└──────┼──────────────────────────────────┘
       │ UDP
       ▼
┌──────────────── Server ────────────────┐
│                                         │
│  elevpn server                          │
│      │ AES-GCM authenticate + decrypt   │
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

현재 작업 중인 elevpn packet은 20바이트 고정 header, 가변 payload, 16바이트 AES-GCM 인증 tag로 구성됩니다. header는 암호화하지 않지만 AAD(Additional Authenticated Data)에 포함해 변조 여부를 검증하고, payload는 암호화와 무결성 검증을 함께 수행합니다.

```text
[message header 20 bytes][encrypted payload variable][AEAD tag 16 bytes]
```

`message header`:

```text
0      version
1      message type
2      flags
3      reserved
4:12   peer ID, uint64, big-endian
12:20  sequence, uint64, big-endian
```

nonce는 방향과 sequence를 결합한 12바이트 값입니다.

```text
0:4   direction, uint32, big-endian
4:12  sequence, uint64, big-endian
```

송신자는 packet을 보낼 때마다 자신의 sequence를 증가시킵니다. 수신자는 peer/session별 마지막 sequence보다 작거나 같은 packet을 replay packet으로 버립니다. 현재 구현은 단순 단조 증가 방식이며, UDP packet 순서 역전을 허용하는 sliding replay window는 아직 적용하지 않았습니다.

message type:

```text
1  ALOHA
2  WELCOME
3  DATA
4  KEEPALIVE
```

현재 작업 중인 `WELCOME` payload:

```text
0:4   client tunnel IPv4
4:6   tunnel MTU, uint16, big-endian
6:22  server random, 16 bytes
```

`DATA` payload:

```text
TUN interface에서 읽은 raw IPv4 packet
```

ALOHA는 서버가 handshake key를 만들 수 있도록 `clientRandom`을 평문으로 전달하되, header와 함께 AAD로 인증합니다.

```text
[message header 20][client random 16][encrypted payload][AEAD tag 16]
```

key 파생은 다음 입력을 사용합니다.

```text
master key    = SHA-256(PSK)
handshake key = HMAC-SHA256(master key, client random)
peer key      = HMAC-SHA256(master key, peer ID || client random || server random)
```

현재 설정된 tunnel MTU는 아직 `1460`입니다. 그러나 DATA packet에 AEAD를 적용하면 IPv4 기준 outer packet 크기는 다음과 같습니다.

```text
outer IPv4 header   20 bytes
UDP header           8 bytes
elevpn header       20 bytes
AEAD tag            16 bytes
----------------------------
overhead            64 bytes

1500 - 64 = 1436
```

따라서 일반적인 MTU 1500 경로에서 outer IP fragmentation을 피하려면 TUN MTU와 `MaxPayloadSize`를 `1436` 이하로 조정해야 합니다. 이 변경과 실제 경로 검증은 AEAD 마무리 단계에 포함돼 있습니다.

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

아래 로그와 네트워크 상태는 현재 AEAD 전환을 시작하기 전에 EC2에서 검증한 안정 버전의 기록입니다. 이 기록에서는 handshake, peer 관리, keepalive, full-tunnel route, NAT와 cleanup까지 확인했습니다. AEAD 작업 브랜치는 WELCOME packet 규격과 MTU 조정을 마친 뒤 같은 절차로 다시 검증할 예정입니다.

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
- 현재 WELCOME은 handshake key를 사용하므로, 동일 ALOHA가 재전송되면 같은 key/nonce로 서로 다른 WELCOME을 만들 위험이 있음
- 현재 sequence 검증은 단순 단조 증가 방식이라 UDP packet 순서 역전을 허용하지 않음
- AEAD overhead를 반영한 TUN MTU와 `MaxPayloadSize` 조정이 아직 남아 있음
- 현재 AEAD 작업 브랜치는 EC2 end-to-end 테스트 전 상태
- DNS 설정 없음
- 영구 설정 파일 없음
- PSK 배포/교체 구조 없음
- SSH 자동 bypass는 TCP local port 22 기준

다음 작업:

- WELCOME에 `serverRandom`을 명시적으로 전달하고 peer key로 암호화하는 handshake 규격 완성
- TUN MTU와 `MaxPayloadSize`를 `1436` 이하로 조정하고 실제 경로에서 검증
- 잘못된 PSK, packet 변조, replay와 nonce 재사용을 검증하는 protocol test 추가
- UDP packet 순서 역전을 허용하는 sliding replay window 검토
- EC2 또는 Linux network namespace 기반 통합 테스트 스크립트 추가
- 부분 실패 상황에서 route rollback 동작 개선
