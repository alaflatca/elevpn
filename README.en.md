# elevpn

Language: [한국어](./README.md) | English

elevpn is a small TUN-over-UDP VPN prototype written in Go.

It creates a Linux TUN interface, wraps IPv4 packets in a simple UDP protocol, sends them to a VPN server, and uses IP forwarding plus nftables masquerade on the server side so client traffic can leave through the server's public network.

This project is not a production VPN. The current goal is to understand and implement the core data path directly:

- TUN device setup
- UDP tunnel transport
- packet authentication and integrity verification with PSK/HMAC-SHA256
- client/server handshake
- peer registration
- full-tunnel route switching
- automatic bypass routes for SSH session continuity
- nftables masquerade
- graceful cleanup

## Current Status

The current MVP can route client traffic through the server.

In the test below, the client EC2 instance public IP was:

```text
3.35.200.113
```

The VPN server EC2 instance public IP was:

```text
54.116.44.5
```

After replacing the client default route with `tun0`, `api.ipify.org` returned the server public IP:

```json
{"ip":"54.116.44.5"}
```

## How It Works

The client starts by sending an `ALOHA` message to the server over UDP.

The server registers the client as a peer, allocates a tunnel IP, and sends back a `WELCOME` message.

```text
client
  -> ALOHA

server
  -> register peer
  -> allocate tunnel IP
  -> WELCOME(peer_id, tunnel_ip, mtu)
```

The overall data flow looks like this:

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

The return path is handled through the server TUN interface and the peer table.

```text
internet response
  -> server
  -> server tun0
  -> destination tunnel IP lookup
  -> peer UDP address
  -> client
  -> client tun0
```

## Route Policy

The client runs in full-tunnel mode. After the VPN is connected, elevpn replaces the default route with `tun0` so regular traffic goes through the tunnel.

To keep the tunnel and remote administration session alive, these destinations are bypassed through the original gateway/interface:

```text
VPN server endpoint /32
current SSH remote IP /32
```

The SSH remote IP is detected through `NETLINK_SOCK_DIAG`/`INET_DIAG` by reading the current TCP socket table. elevpn looks for `ESTABLISHED` connections on `local port 22` and adds the remote IP as a `/32` route.

```text
54.116.44.5/32 via 172.31.48.1 dev ens5
221.167.251.145/32 via 172.31.48.1 dev ens5
default dev tun0
```

This keeps SSH reachable even when `sudo` drops environment variables such as `SSH_CLIENT`.

## Protocol

Every elevpn packet sent over UDP contains a small fixed header, a variable payload, and an HMAC tag.

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

The HMAC tag is calculated over the full `message header + payload`. The receiver recalculates the HMAC-SHA256 tag with the same PSK and compares it with the received tag to verify packet authenticity and integrity.

Message types:

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
raw IPv4 packet read from the TUN interface
```

The current tunnel MTU is `1460`.

```text
outer IPv4 header   20 bytes
UDP header           8 bytes
elevpn header       12 bytes
----------------------------
overhead            40 bytes

1500 - 40 = 1460
```

The initial implementation lowered the TUN MTU to 1460 based on the outer IPv4, UDP, and elevpn header overhead.

With the HMAC tag added, each UDP packet now has 32 more bytes at the end. This is still a prototype validation stage, and `MaxPayloadSize`/TUN MTU should be recalculated against the outer packet size in a follow-up step.

## Build

Build for Linux x86_64:

```bash
GOOS=linux GOARCH=amd64 go build -o bin/elevpn .
```

The program needs privileges to create TUN devices, modify routes, enable IP forwarding, and update nftables rules. The examples below use `sudo`.

## Run

Server:

```bash
sudo ./elevpn server --psk test-secret
```

Client:

```bash
sudo ./elevpn client --server-endpoint=54.116.44.5:9010 --psk test-secret
```

The server and client must use the same `--psk` value. The default `test-secret` is only for quick testing.

## Test Run

Server log:

```text
[ec2-user@ip-172-31-52-136 ~]$ sudo ./elevpn server --psk test-secret
2026/08/03 13:12:29 [init] listen=0.0.0.0:9010 tun-name=tun0 vpn-network-cidr=10.77.0.0/24
2026/08/03 13:12:29 [route] default interface=ens5 index=2 gateway="172.31.48.1"
2026/08/03 13:12:44 [handshake] received ALOHA from 3.35.200.113:47624
2026/08/03 13:12:44 [handshake] registered peer id=1 tunnel_ip=10.77.0.2 mtu=1460
2026/08/03 13:12:44 [handshake] sent WELCOME peer_id=1 tunnel_ip=10.77.0.2 mtu=1460
2026/08/03 13:12:54 [keepalive] peer_id=1 last_seen updated
```

Client log:

```text
[ec2-user@ip-172-31-50-229 ~]$ sudo ./elevpn client --server-endpoint=54.116.44.5:9010 --psk test-secret
2026/08/03 13:12:44 [init] listen=:0 endpoint=54.116.44.5:9010 tunName=tun0
2026/08/03 13:12:44 [handshake] sent ALOHA to 54.116.44.5:9010
2026/08/03 13:12:44 [handshake] received WELCOME peer_id=1 tunnel_ip=10.77.0.2 mtu=1460
2026/08/03 13:12:44 [route] default interface=ens5 index=2 gateway="172.31.48.1"
2026/08/03 13:12:44 [route] detected ssh bypass cidrs=[54.116.44.5/32 221.167.251.145/32]
```

## Interface State

Server TUN interface:

```text
[ec2-user@ip-172-31-52-136 ~]$ ip addr show tun0
11: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1460 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.77.0.1/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::1b5c:be8e:70f9:dbed/64 scope link stable-privacy proto kernel_ll
       valid_lft forever preferred_lft forever
```

Client TUN interface:

```text
[ec2-user@ip-172-31-50-229 ~]$ ip addr show tun0
8: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1460 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.77.0.2/32 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::4591:5d54:ec2a:9ddc/64 scope link stable-privacy proto kernel_ll
       valid_lft forever preferred_lft forever
```

## Route State

Server routes:

```text
[ec2-user@ip-172-31-52-136 ~]$ ip route show
default via 172.31.48.1 dev ens5 proto dhcp src 172.31.52.136 metric 512
10.77.0.0/24 dev tun0 proto kernel scope link src 10.77.0.1
172.31.0.2 via 172.31.48.1 dev ens5 proto dhcp src 172.31.52.136 metric 512
172.31.48.0/20 dev ens5 proto kernel scope link src 172.31.52.136 metric 512
172.31.48.1 dev ens5 proto dhcp scope link src 172.31.52.136 metric 512
```

Client routes:

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

The VPN server endpoint and the SSH remote IP are kept outside the tunnel:

```text
54.116.44.5 via 172.31.48.1 dev ens5 proto static
221.167.251.145 via 172.31.48.1 dev ens5 proto static
```

These routes keep the UDP tunnel and SSH connection reachable even after the default route is moved to `tun0`.

## NAT Rule

On the server, elevpn creates an nftables masquerade rule for the VPN network.

```text
[ec2-user@ip-172-31-52-136 ~]$ sudo nft list ruleset
table ip vpnnat {
        chain vpn-postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip saddr 10.77.0.0/24 oifname "ens5" masquerade
        }
}
```

This means packets from the VPN network are rewritten to use the server's external interface when they leave through `ens5`.

## External IP Test

After full-tunnel routing is applied, no manual test route is needed.

```bash
curl -s https://api.ipify.org?format=json
```

Result:

```json
{"ip":"54.116.44.5"}
```

The returned IP is the VPN server public IP, so the request went through the tunnel and exited from the server.

## Cleanup

Client shutdown:

```text
^C2026/08/03 13:18:00 [Route] elapsed time: 509.09µs
2026/08/03 13:18:00 [tun0] tun interface close
2026/08/03 13:18:00 [tun0] elapsed time: 59.091121ms
2026/08/03 13:18:00 uptime: 5m16.476614408s
```

Server shutdown:

```text
^C2026/08/03 13:18:15 runTunnel end (context.Canceled)
2026/08/03 13:18:15 [Masquerade (vpnnat)] elapsed time: 16.14482ms
2026/08/03 13:18:15 [IPForward] elapsed time: 152.742µs
2026/08/03 13:18:15 [tun0] tun interface close
2026/08/03 13:18:15 [tun0] elapsed time: 39.847988ms
2026/08/03 13:18:15 uptime: 5m46.301056623s
```

## Notes

Current limitations:

- IPv4 only
- no payload encryption yet
- no replay attack protection yet
- no DNS configuration
- no persistent config file
- no PSK distribution or rotation mechanism
- automatic SSH bypass currently assumes TCP local port 22

Next steps:

- add sequence numbers or nonces
- evaluate AEAD-based payload encryption
- add integration test scripts for EC2 or Linux network namespaces
- improve route rollback behavior around partial failures
