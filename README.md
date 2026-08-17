# elevpn

언어: 한국어 | [English](./README.en.md)

elevpn은 Go로 만든 Linux TUN-over-UDP VPN 프로토타입입니다.

클라이언트의 IPv4 패킷을 TUN 인터페이스에서 읽어 AES-GCM으로 암호화한 뒤 UDP로 서버에 전달합니다. 서버는 패킷을 복호화해 Linux network stack으로 넘기고, IP forwarding과 nftables masquerade를 통해 외부 인터넷으로 전달합니다.

운영용 VPN보다는 데이터 경로를 직접 구현하고 확인하는 데 초점을 둔 프로젝트입니다. TUN, UDP, routing, NAT, Netlink, packet framing과 암호화가 실제로 어떻게 이어지는지 공부하며 기능을 확장하고 있습니다.

- Linux TUN device 생성과 MTU 설정
- UDP 기반 tunnel transport
- PSK에서 파생한 AES-256-GCM key로 packet 암호화 및 인증
- `ALOHA`/`WELCOME` handshake와 peer별 session key
- peer 등록, tunnel IP 할당, keepalive와 만료 처리
- sequence number 기반 replay packet 차단
- full-tunnel route와 SSH 연결 보호용 bypass route
- IP forwarding과 nftables masquerade
- non-blocking TUN, `poll`/`eventfd` 기반 빠른 종료
- 적용 역순 cleanup

## 현재 상태

2026년 8월 17일 AWS EC2의 client/server 환경에서 다음 흐름을 확인했습니다.

- `ALOHA`, `WELCOME`, `DATA`, `KEEPALIVE`의 AES-GCM 인증 및 암복호화
- `clientRandom`과 `serverRandom`을 사용한 handshake별 key 분리
- peer ID와 양쪽 random을 사용한 peer별 DATA key 파생
- TUN MTU와 `MaxPayloadSize`를 `1436`으로 적용
- VPN 연결 후에도 기존 SSH session과 새 SSH session 유지
- full-tunnel을 통한 외부 인터넷 통신
- `api.ipify.org`에서 VPN 서버의 공인 IP 반환
- `tun0`에서는 HTTP 평문, 외부 NIC의 UDP 9010에서는 암호문 확인

```bash
curl -s http://api.ipify.org?format=json
```

```json
{"ip":"3.38.43.231"}
```

## 데이터 흐름

```text
┌──────────────── Client ────────────────┐
│                                        │
│  Application                           │
│      │                                 │
│      ▼                                 │
│  Kernel route                          │
│      │                                 │
│      ▼                                 │
│  tun0                                  │
│      │ raw IPv4 packet                 │
│      ▼                                 │
│  elevpn client                         │
│      │ AES-GCM encrypt + authenticate  │
│      ▼                                 │
└──────┼─────────────────────────────────┘
       │ UDP 9010
       ▼
┌──────────────── Server ────────────────┐
│                                        │
│  elevpn server                         │
│      │ authenticate + decrypt          │
│      ▼                                 │
│  tun0                                  │
│      │ raw IPv4 packet                 │
│      ▼                                 │
│  IP forwarding                         │
│      ▼                                 │
│  nftables masquerade                   │
│      ▼                                 │
│  Internet                              │
│                                        │
└────────────────────────────────────────┘
```

응답은 반대 순서로 전달됩니다.

```text
Internet response
  -> server external interface
  -> conntrack/NAT destination restore
  -> server tun0
  -> destination tunnel IP로 peer 조회
  -> peer UDP address로 암호화해 전송
  -> client에서 복호화
  -> client tun0
  -> application
```

TUN에서는 항상 평문의 inner IP packet을 다룹니다. 암호화와 복호화는 elevpn이 TUN과 UDP socket 사이에서 수행합니다.

## Handshake

Handshake는 ALOHA와 WELCOME 두 단계로 진행됩니다.

```text
Client
  -> clientRandom 생성
  -> AlohaCipher(PSK, clientRandom) 생성
  -> ALOHA(sequence=1) 전송

Server
  -> clientRandom으로 ALOHA 인증
  -> peer 등록, tunnel IP 할당
  -> serverRandom 생성
  -> WelcomeCipher(PSK, clientRandom, serverRandom) 생성
  -> WELCOME(sequence=1) 전송

Client / Server
  -> PeerCipher(PSK, peer ID, clientRandom, serverRandom) 생성
  -> DATA와 KEEPALIVE 송수신
```

ALOHA와 WELCOME에 서로 다른 key를 사용합니다. WELCOME key에는 서버가 매 handshake마다 생성하는 `serverRandom`이 들어가므로, 동일한 ALOHA가 다시 들어와도 같은 key와 nonce로 서로 다른 WELCOME payload를 암호화하지 않습니다.

## Packet Format

공통 message header는 20바이트입니다.

```text
0       version
1       message type
2       flags
3       reserved
4:12    peer ID, uint64, big-endian
12:20   sequence, uint64, big-endian
```

Message type:

```text
1  ALOHA
2  WELCOME
3  DATA
4  KEEPALIVE
```

### DATA / KEEPALIVE

```text
[header 20][encrypted payload variable][AEAD tag 16]
```

Header는 암호화하지 않지만 AAD(Additional Authenticated Data)로 인증합니다. DATA payload에는 TUN에서 읽은 raw IPv4 packet이 들어갑니다.

### ALOHA

```text
[header 20][clientRandom 16][encrypted payload][AEAD tag 16]
└──────────────── AAD ────────────────┘
```

서버가 ALOHA key를 만들 수 있도록 `clientRandom`은 평문으로 전달하며, header와 함께 AAD에 넣어 변조를 검증합니다.

### WELCOME

```text
[header 20][serverRandom 16][encrypted WELCOME payload][AEAD tag 16]
└──────────────── AAD ────────────────┘
```

클라이언트가 WELCOME key를 만들 수 있도록 `serverRandom`은 평문으로 전달하며 AAD로 인증합니다.

복호화된 WELCOME payload는 6바이트입니다.

```text
0:4  client tunnel IPv4
4:6  tunnel MTU, uint16, big-endian
```

## Key와 Nonce

현재 key 파생 입력은 다음과 같습니다.

```text
master key  = SHA-256(PSK)
ALOHA key   = HMAC-SHA256(master key, clientRandom)
WELCOME key = HMAC-SHA256(master key, clientRandom || serverRandom)
peer key    = HMAC-SHA256(master key,
                          peer ID || clientRandom || serverRandom)
```

AES-GCM nonce는 방향과 sequence를 결합한 12바이트 값입니다.

```text
0:4   direction, uint32, big-endian
4:12  sequence, uint64, big-endian
```

클라이언트와 서버는 송신 sequence와 마지막 수신 sequence를 방향별로 따로 관리합니다. 현재는 수신 sequence가 마지막 값보다 작거나 같으면 replay packet으로 버립니다.

## MTU

외부 IPv4 경로의 MTU를 1500으로 가정하고 DATA packet의 최대 크기를 계산합니다.

```text
outer IPv4 header        20 bytes
UDP header                8 bytes
elevpn header            20 bytes
encrypted inner packet 1436 bytes
AEAD tag                 16 bytes
---------------------------------
outer IPv4 packet      1500 bytes
```

```text
1500 - 20 - 8 - 20 - 16 = 1436
```

계산한 `1436`을 TUN MTU와 `MaxPayloadSize`로 사용해 일반적인 MTU 1500 경로에서 elevpn DATA packet 때문에 외부 IP fragmentation이 발생하지 않도록 했습니다.

## Route 정책

클라이언트는 VPN 연결 후 default route를 `tun0`로 변경하는 full-tunnel 방식으로 동작합니다.

다만 UDP tunnel과 SSH 접속이 끊기지 않도록 다음 주소는 기존 gateway와 interface로 우회합니다.

```text
VPN server endpoint /32
현재 SSH 접속자의 remote IP /32
```

SSH remote IP는 `NETLINK_SOCK_DIAG`/`INET_DIAG`로 커널의 TCP socket 목록을 조회해 찾습니다. `local port 22`의 `ESTABLISHED` 연결을 찾아 remote IP를 `/32` route로 추가하므로 `sudo`가 `SSH_CLIENT` 환경변수를 전달하지 않는 경우에도 동작합니다.

```text
<server-ip> via <gateway> dev <real-nic>
<ssh-client-ip> via <gateway> dev <real-nic>
default dev tun0
```

## Build

Linux x86_64:

```bash
GOOS=linux GOARCH=amd64 go build -o bin/elevpn .
```

TUN 생성, route 변경, IP forwarding과 nftables 설정에 관리자 권한이 필요합니다.

## Run

서버:

```bash
sudo ./elevpn server --psk test-secret
```

클라이언트:

```bash
sudo ./elevpn client \
  --server-endpoint=<server-public-ip>:9010 \
  --psk test-secret
```

서버와 클라이언트는 같은 PSK를 사용해야 합니다. 기본값 `test-secret`은 테스트 편의를 위한 값이며 운영 환경에 적합하지 않습니다.

## Verification

### 외부 IP

```bash
curl -s http://api.ipify.org?format=json
```

EC2 검증 결과:

```json
{"ip":"3.38.43.231"}
```

VPN 서버의 공인 IP가 반환되어 client traffic이 tunnel과 서버 NAT를 거쳐 외부로 나간 것을 확인했습니다.

### TUN 평문

```bash
sudo tcpdump -ni tun0 -s 0 -A 'tcp port 80'
```

`tun0`에서는 복호화된 HTTP 응답을 확인할 수 있습니다.

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"ip":"3.38.43.231"}
```

### UDP 암호문

```bash
sudo tcpdump -ni <real-nic> -s 0 -XX 'udp port 9010'
```

캡처한 DATA packet 중 하나는 다음 값을 가졌습니다.

```text
UDP payload length  96
protocol version     1
message type         3 (DATA)
peer ID              1
sequence             65
```

20바이트 elevpn header 뒤에는 암호화된 inner packet과 16바이트 AEAD tag가 이어졌습니다. 외부 NIC의 UDP payload에서는 `GET`, `Host`, `api.ipify.org`와 응답 JSON 같은 HTTP 평문이 나타나지 않았습니다.

### 네트워크 상태

```bash
ip addr show dev tun0
ip route show table main
cat /proc/sys/net/ipv4/ip_forward
sudo nft list table ip vpnnat
sudo ss -lunp | grep 9010
```

서버가 만드는 NAT rule의 형태는 다음과 같습니다.

```text
table ip vpnnat {
        chain vpn-postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip saddr 10.77.0.0/24 oifname "<real-nic>" masquerade
        }
}
```

## 현재 제한사항

- IPv4만 지원
- PSK를 CLI로 공유하며 별도의 배포·교체 체계가 없음
- 단순 단조 증가 sequence 검증이라 순서가 뒤바뀐 정상 UDP packet도 버림
- 캡처한 ALOHA의 반복 전송을 제한하는 handshake rate limit 없음
- DNS 설정을 별도로 변경하지 않음
- 영구 설정 파일 없음
- SSH 자동 bypass는 TCP local port 22 기준
- route 적용 중 부분 실패에 대한 내부 rollback 보강 필요
- protocol과 end-to-end 자동 테스트 보강 필요

## 다음 작업

- out-of-order UDP packet을 허용하는 sliding replay window
- handshake replay 제한과 rate limit
- 잘못된 PSK, packet 변조, replay, nonce 재사용에 대한 protocol test
- Linux network namespace 기반 end-to-end test
- route 부분 실패 rollback 개선
