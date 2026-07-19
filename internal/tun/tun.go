//go:build linux

package tun

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

type Tun struct {
	name       string
	cidr       string
	actualName string

	f *os.File
}

func New(name string, cidr string) (*Tun, error) {
	if name == "" {
		return nil, fmt.Errorf("tun name is empty")
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cidr(%q): %v", cidr, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("tun cidr must be IPv4: %q", cidr)
	}

	return &Tun{name: name, cidr: cidr}, nil
}

func (t *Tun) Apply() error {
	if err := t.create(); err != nil {
		return err
	}

	if err := t.setIPv4CIDR(t.cidr); err != nil {
		return err
	}

	if err := t.up(); err != nil {
		return err
	}

	return nil
}

func (t *Tun) Cleanup() error {
	if t == nil || t.f == nil {
		return nil
	}

	err := t.f.Close()
	if err != nil {
		return err
	}
	t.f = nil

	log.Printf("[%s] tun interface close", t.name)
	return nil
}

func (t *Tun) Name() string {
	return t.name
}

func (t *Tun) create() error {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open /dev/net/tun: %v", err)
	}

	ifr, err := unix.NewIfreq(t.name)
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("new ifreq: %v", err)
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)

	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return fmt.Errorf("ioctl(TUNSETIFF): %v", err)
	}

	t.actualName = ifr.Name()
	t.f = os.NewFile(uintptr(fd), "/dev/net/tun")

	return nil
}

func (t *Tun) setIPv4CIDR(cidr string) error {
	if t == nil || t.f == nil {
		return fmt.Errorf("nil device")
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", cidr, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 CIDR is supported: %q", cidr)
	}

	mask4 := net.IP(ipnet.Mask).To4()
	if mask4 == nil {
		return fmt.Errorf("invalid IPv4 mask in CIDR: %q", cidr)
	}

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket(AF_INET, SOCK_DGRAM): %w", err)
	}
	defer unix.Close(sock)

	// TUN 인터페이스에 IPv4 추가
	ifr, err := unix.NewIfreq(t.name)
	if err != nil {
		return fmt.Errorf("new ifreq(addr): %w", err)
	}
	if err := ifr.SetInet4Addr(ip4); err != nil {
		return fmt.Errorf("SetInet4Addr(addr): %w", err)
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFADDR, ifr); err != nil {
		return fmt.Errorf("ioctl(SIOCSIFADDR): %w", err)
	}

	// TUN 인터페이스에  Subnet Mask 추가
	ifr, err = unix.NewIfreq(t.name)
	if err != nil {
		return fmt.Errorf("new ifreq(mask): %w", err)
	}
	if err := ifr.SetInet4Addr(mask4); err != nil {
		return fmt.Errorf("SetInet4Addr(mask): %w", err)
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFNETMASK, ifr); err != nil {
		return fmt.Errorf("ioctl(SIOCSIFNETMASK): %w", err)
	}

	return nil
}

func (t *Tun) up() error {
	if t == nil || t.f == nil {
		return fmt.Errorf("nil device")
	}

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(sock)

	ifr, err := unix.NewIfreq(t.name)
	if err != nil {
		return fmt.Errorf("new ifreq: %w", err)
	}

	if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SICOCGIFFLAGS: %w", err)
	}

	flags := ifr.Uint16()
	ifr.SetUint16(flags | unix.IFF_UP) // 기존 플래그에서  IFF_UP 플래그 추가

	if err := unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SICOCSIFFLAGS: %w", err)
	}

	return nil
}

func (t *Tun) WriteContext(ctx context.Context, b []byte) (int, error) {
	if t == nil || t.f == nil {
		return 0, errors.New("tun file is nil")
	}

	return t.f.Write(b)
}

// context.AfterFunc -> tunDevice.Cleanup이 실행되어도
// tunToUdp의 tunDevice.Read를 즉시 깨우지 않음 (client, server)
// tunToUdp의 blocking Read가 Close 이후 늦게 반환됨 ( udp socket 은 즉시 깨움 )
// 서비스 종료에 많은 시간 소요됨

func (t *Tun) ReadContext(ctx context.Context, b []byte, eventFd int) (int, error) {
	if t == nil || t.f == nil {
		return 0, errors.New("tun file is nil")
	}

	// eventfd  추가 필요함
	fds := []unix.PollFd{
		{Fd: int32(eventFd), Events: unix.POLLIN},  // index 0
		{Fd: int32(t.f.Fd()), Events: unix.POLLIN}, // index 1
	}

	for {
		_, err := unix.Poll(fds, -1)
		if err != nil {
			// syscall이 signal handler 실행 때문에 중단됨
			// 커널이 syscall을 완료하지 않고 -1/EINTR로 반환함
			if errors.Is(err, unix.EINTR) {
				continue
			}
			// fd가 O_NONBLOCK 상태
			// read 호출했지만 현재 읽은 packet이 없음
			// 커널이 block하지 않고 -1/EAGAIN 반환
			if errors.Is(err, unix.EAGAIN) {
				continue
			}
			// 요청한 작업은 blocking될 상황이다ㅣ.
			// 하지만 fd가 non-blocking이므로 block하지 않고 반환한다.
			if errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return 0, fmt.Errorf("failed to tun poll: %w", err)
		}

		for i, fd := range fds {
			revents := fds[i].Revents

			if revents == 0 {
				continue
			}
			// fd가 유효하지 않음 (닫힌 fd이거나 잘못된 fd 번호일 때 발생할 수 있음)
			if revents&unix.POLLNVAL != 0 {
				return 0, fmt.Errorf("tun poll invalid fd (POLLNVAL), fds=%d", i)
			}
			// fd에 에러 상태가 발생함 (장치나 소켓 레벨에서 오류가 있음을 의미함)
			if revents&unix.POLLERR != 0 {
				return 0, fmt.Errorf("tun poll error event (POLLERR), fds=%d", i)
			}
			// 읽을 데이터가 있음 (지금 read를 호출하면 block되지 않고 데이터를 읽을 수 있음을 의미함)
			if revents&unix.POLLIN != 0 {
				if i == 0 { // event fd
					var eventBuf [8]byte
					_, err := unix.Read(int(fd.Fd), eventBuf[:])
					if err != nil {
						return 0, err
					}
					return 0, context.Canceled

				}
				if i == 1 { // tun fd
					return t.f.Read(b)
				}
			}
			// hang up 상태 (상대나 장치가 닫혔거나 더 이상 정상적인 I/O가 불가능한 상태를 의미함)
			if revents&unix.POLLHUP != 0 {
				return 0, fmt.Errorf("tun poll hangup (POLLHUP), fds=%d", i)
			}
			return 0, fmt.Errorf("unexpected poll event: revents=%v", revents)
		}
	}
}

/*
이유:

tunTodup는 tunDevice.Read()에서 blocking 상태로 대기
 -> tun.Read()
 -> TUN에 packet이 들어올 때까지 block

 Ctrl+c가 오면 context는 cancel되지만, tunToUdp goruntine은 이미
 tuneDevice.Read() 호출에서 block 중이다.
 Read가 반환되기 전까지는 함수의 다음 줄로 진행하지 못하므로 ctx.Err()를 확인할 수 없다.

현재는 AfterFunc에서 tundevice.Cleanup()을 호출해서 TUN fd를 닫고,
그 결과로 Read()가 깨어나기를 기대함.

문제는 TUN fd는 일반 socket이 아니라 /dev/net/tun character device라서, 다른 goroutine에서
Close() 했다고 해서 blocking Read() 가 즉시 깨어난다고 강하게 기대하기 어렵다

Ctrl+c
-> context cancel
-> tun fd Close
-> 하지만 tun.Read가 늦게 반환
-> errGroup.Wait가 계속 대기
-> Teardown도 늦게 실행

* Close를 goroutine 종료 신호처럼 사용하고 있다.
하지만 TUN blocking Read는 Close에 즉시 반응한다고 보장하기 어렵다.




TUN Read는 TUN 드라이버의 wait queue에서 기다림
Close는 fd reference를 닫는 작업
blocking read를 즉시 interrupt하는 방식은 fd 종류/드라이버 구현/런타임 처리에 따라 다를 수 있음
Go의 os.File.Read는 context-aware하지 않음


해결법:

1. TUN fd를 non-blocking으로 연다 (현재는 blocking 모드)
2. poll로 TUN fd가 readable인지 기다린다.
3. context cancel은 eventfd에 write 해서 poll을 깨운다.
4. poll 결과가:
   - tun fd readable이면 tun.Read()
   - eventfd readble이면 context.Canceled 반환
5. TUN Cleanup은 goroutine을 깨우기 위한 용도가 아니라 최종 리소스 정리 용도로만 사용한다.

eventfd:
	cancel 신호로 poll을 깨우는 용도
poll:
	tun fd에 읽을 packet이 있는지 확인하는 용도
tun.Close:
	최종 fd 정리 용도


=================
**** readable 이란 ****
user process
	|
	| poll(fd: tunFd, events: POLLIN)
	v
kernel
	|
	| 1. 현재 프로세스의 fd table 조회 (프로세스마다 자기 fd table을 가지고있음)
	v
fd table
	|
	| tunFd -> struct file
	v
struct file
	|
	| 2. file->f_op->poll(file, poll_table) 호출
	v
TUN driver poll 함수
	|
	| 3. poll_wait(file, tun_wait_queue, poll_table)
	|	현재 task를 TUN wait queue에 등록
	|
	| 4. TUN packet queue 확인
	|
	|	packet 있음
	|		-> POLLIN 반환
	|
	|	packet 없음
	|		-> 0 반환
	v
kernel poll core
	|
	| 5. POLLIN 있으면 user에게 즉시 반환
	|
	| 6. 이벤트 없으면 현재 task를 sleep
	v
나중에 packet 도착
	|
	v
TUN driver
	|
	| TUN queue에 packet 추가
	| wake_up(tun_wait_queue)
	v
kernel poll core
	|
	| sleep 중인 task 깨어남
	| 다시 상태 확인
	| revents = POLLIN 설정
	v
user process
	|
	| poll 반환
	| revents에 POLLIN 있음
	v
tun.Read()

*/
