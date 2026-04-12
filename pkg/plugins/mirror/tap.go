package mirror

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func OpenTap(interfaceName string) (*os.File, error) {
	// Open the TAP device for reading and writing
	tapHandle, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(interfaceName)
	if err != nil {
		unix.Close(tapHandle)
		return nil, fmt.Errorf("failed to create ifreq: %w", err)
	}

	// Set the TAP device flags (IFF_TAP | IFF_NO_PI)
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)

	// Issue ioctl
	if err := unix.IoctlIfreq(tapHandle, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(tapHandle)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %w", err)
	}

	return os.NewFile(uintptr(tapHandle), interfaceName), nil
}
