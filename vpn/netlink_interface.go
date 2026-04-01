package vpn

import "golang.org/x/sys/unix"

func GetDefaultExternalInterface(fd int) (string, error) {
	rtmsg := newBaseRtmsg()
	header := rtgen(rtmsg)
	packet := nlMsg(1, unix.RTM_GETROUTE, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, header)

	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return "", err
	}

	recvRoutesAck(fd, 1)

	return "", nil
}

func recvRoutesAck(fd int, want ...uint32) error {
	buf := make([]byte, 64*1024)

	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {

	}

	return nil
}
