# elevpn

Language: [한국어](./README.md) | English

elevpn is a Linux TUN-over-UDP VPN prototype written in Go.

The client reads IPv4 packets from a TUN interface, encrypts them with AES-GCM, and sends them to the server over UDP. The server decrypts the packets, feeds them into the Linux network stack, and forwards them to the Internet using IP forwarding and nftables masquerade.

The project is intended for learning and validating the VPN data path rather than production use. It implements and connects TUN, UDP transport, routing, NAT, Netlink, packet framing, and authenticated encryption directly.

- Linux TUN device creation and MTU configuration
- UDP tunnel transport
- AES-256-GCM packet encryption and authentication with PSK-derived keys
- `ALOHA`/`WELCOME` handshake and per-peer session keys
- peer registration, tunnel IP allocation, keepalive, and expiration
- sequence-number-based replay rejection
- full-tunnel routing with automatic SSH bypass routes
- IP forwarding and nftables masquerade
- responsive shutdown using non-blocking TUN, `poll`, and `eventfd`
- reverse-order cleanup

## Current Status

The following flow was verified on AWS EC2 on August 17, 2026:

- authenticated encryption for `ALOHA`, `WELCOME`, `DATA`, and `KEEPALIVE`
- per-handshake key separation using `clientRandom` and `serverRandom`
- per-peer DATA keys derived with the peer ID and both random values
- TUN MTU and `MaxPayloadSize` set to `1436`
- existing and new SSH sessions remain available after full-tunnel activation
- Internet access through the VPN server
- `api.ipify.org` returns the VPN server public IP
- HTTP plaintext is visible on `tun0`, while UDP port 9010 carries ciphertext on the external NIC

```bash
curl -s http://api.ipify.org?format=json
```

```json
{"ip":"3.38.43.231"}
```

## Data Flow

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

The response follows the reverse path:

```text
Internet response
  -> server external interface
  -> conntrack/NAT destination restore
  -> server tun0
  -> peer lookup by destination tunnel IP
  -> encrypted UDP packet to the peer address
  -> client decrypts the packet
  -> client tun0
  -> application
```

TUN always carries plaintext inner IP packets. elevpn performs encryption and decryption between the TUN interface and the UDP socket.

## Handshake

The handshake consists of ALOHA and WELCOME:

```text
Client
  -> generate clientRandom
  -> create AlohaCipher(PSK, clientRandom)
  -> send ALOHA(sequence=1)

Server
  -> authenticate ALOHA with clientRandom
  -> register peer and allocate tunnel IP
  -> generate serverRandom
  -> create WelcomeCipher(PSK, clientRandom, serverRandom)
  -> send WELCOME(sequence=1)

Client / Server
  -> create PeerCipher(PSK, peer ID, clientRandom, serverRandom)
  -> exchange DATA and KEEPALIVE packets
```

ALOHA and WELCOME use separate keys. The WELCOME key includes a new `serverRandom` for each handshake, preventing different WELCOME payloads from being encrypted with the same key and nonce when an ALOHA packet is replayed.

## Packet Format

Every message starts with a fixed 20-byte header:

```text
0       version
1       message type
2       flags
3       reserved
4:12    peer ID, uint64, big-endian
12:20   sequence, uint64, big-endian
```

Message types:

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

The header remains visible but is authenticated as AAD. A DATA payload contains the raw IPv4 packet read from TUN.

### ALOHA

```text
[header 20][clientRandom 16][encrypted payload][AEAD tag 16]
└──────────────── AAD ────────────────┘
```

`clientRandom` is sent in plaintext so the server can derive the ALOHA key. It is authenticated together with the header as AAD.

### WELCOME

```text
[header 20][serverRandom 16][encrypted WELCOME payload][AEAD tag 16]
└──────────────── AAD ────────────────┘
```

`serverRandom` is sent in plaintext so the client can derive the WELCOME key. It is also authenticated as AAD.

The decrypted WELCOME payload is six bytes:

```text
0:4  client tunnel IPv4
4:6  tunnel MTU, uint16, big-endian
```

## Keys and Nonces

The current key derivation inputs are:

```text
master key  = SHA-256(PSK)
ALOHA key   = HMAC-SHA256(master key, clientRandom)
WELCOME key = HMAC-SHA256(master key, clientRandom || serverRandom)
peer key    = HMAC-SHA256(master key,
                          peer ID || clientRandom || serverRandom)
```

The 12-byte AES-GCM nonce combines packet direction and sequence number:

```text
0:4   direction, uint32, big-endian
4:12  sequence, uint64, big-endian
```

The client and server maintain independent send and last-received sequences for each direction. A packet is rejected as a replay when its sequence is less than or equal to the last accepted value.

## MTU

The DATA packet budget assumes an outer IPv4 MTU of 1500:

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

Both the TUN MTU and `MaxPayloadSize` use `1436`, avoiding outer IP fragmentation caused by elevpn DATA overhead on a typical MTU 1500 path.

## Route Policy

The client switches its default route to `tun0` after the VPN connects. The VPN server endpoint and current SSH remote addresses bypass the tunnel through the original gateway and interface.

```text
VPN server endpoint /32
current SSH remote IP /32
```

The SSH remote IP is discovered through `NETLINK_SOCK_DIAG`/`INET_DIAG` by finding `ESTABLISHED` TCP connections on local port 22. This does not depend on `SSH_CLIENT` being preserved by `sudo`.

```text
<server-ip> via <gateway> dev <real-nic>
<ssh-client-ip> via <gateway> dev <real-nic>
default dev tun0
```

## Build

```bash
GOOS=linux GOARCH=amd64 go build -o bin/elevpn .
```

Administrative privileges are required to create TUN devices, modify routes, enable IP forwarding, and configure nftables.

## Run

Server:

```bash
sudo ./elevpn server --psk test-secret
```

Client:

```bash
sudo ./elevpn client \
  --server-endpoint=<server-public-ip>:9010 \
  --psk test-secret
```

The server and client must use the same PSK. The default `test-secret` exists for testing only and is not suitable for production.

## Verification

### External IP

```bash
curl -s http://api.ipify.org?format=json
```

EC2 result:

```json
{"ip":"3.38.43.231"}
```

The returned address is the VPN server public IP, confirming that client traffic traversed the tunnel and exited through the server NAT.

### TUN Plaintext

```bash
sudo tcpdump -ni tun0 -s 0 -A 'tcp port 80'
```

The decrypted response is visible on `tun0`:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"ip":"3.38.43.231"}
```

### UDP Ciphertext

```bash
sudo tcpdump -ni <real-nic> -s 0 -XX 'udp port 9010'
```

One captured DATA packet contained:

```text
UDP payload length  96
protocol version     1
message type         3 (DATA)
peer ID              1
sequence             65
```

The 20-byte elevpn header was followed by the encrypted inner packet and a 16-byte AEAD tag. HTTP plaintext such as `GET`, `Host`, `api.ipify.org`, and the response JSON did not appear in the UDP payload on the external NIC.

### Network State

```bash
ip addr show dev tun0
ip route show table main
cat /proc/sys/net/ipv4/ip_forward
sudo nft list table ip vpnnat
sudo ss -lunp | grep 9010
```

The server creates an nftables rule in this form:

```text
table ip vpnnat {
        chain vpn-postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip saddr 10.77.0.0/24 oifname "<real-nic>" masquerade
        }
}
```

## Current Limitations

- IPv4 only
- PSKs are shared through the CLI without a distribution or rotation mechanism
- strictly increasing sequence validation drops valid out-of-order UDP packets
- no handshake rate limit for repeated captured ALOHA packets
- no separate DNS configuration
- no persistent configuration file
- automatic SSH bypass assumes TCP local port 22
- route rollback around partial failures needs improvement
- protocol and end-to-end automated tests need more coverage

## Next Steps

- sliding replay window for out-of-order UDP packets
- handshake replay limits and rate limiting
- protocol tests for wrong PSKs, packet tampering, replay, and nonce reuse
- Linux network namespace end-to-end tests
- stronger rollback for partial route failures
