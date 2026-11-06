//go:build linux

package quic

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"golang.org/x/sys/unix"
)

// scriptedRawConn fails the first write with err and succeeds afterwards. A
// writer that keeps going is cut off after 100 calls, so a regression fails
// the test instead of hanging it.
type scriptedRawConn struct {
	rawConn
	err    error
	writes [][]byte
}

func (c *scriptedRawConn) WritePacket(b []byte, _ net.Addr, _ []byte, _ uint16, _ protocol.ECN) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	switch {
	case len(c.writes) == 1:
		return 0, c.err
	case len(c.writes) > 100:
		return 0, errors.New("still writing after 100 calls")
	}
	return len(b), nil
}

func (c *scriptedRawConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}
}

func newScriptedSendConn(err error) (*sconn, *scriptedRawConn) {
	raw := &scriptedRawConn{err: err}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	return newSendConn(raw, remote, packetInfo{}, utils.DefaultLogger), raw
}

// On a router without GSO, a PPPoE interface torn down mid-send failed one
// write with EIO; the GSO fallback then split the packet into gsoSize (0)
// pieces and sent empty datagrams in a loop that never ended.
func TestWriteWithoutGSOReturnsTheError(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EIO, unix.EINVAL} {
		conn, raw := newScriptedSendConn(os.NewSyscallError("sendmsg", errno))
		err := conn.Write(make([]byte, 1200), 0, protocol.ECNUnsupported)
		if !errors.Is(err, errno) {
			t.Fatalf("%v: Write returned %v, want the error itself", errno, err)
		}
		if len(raw.writes) != 1 {
			t.Fatalf("%v: %d writes, want 1", errno, len(raw.writes))
		}
		if conn.gotGSOError {
			t.Fatalf("%v: GSO marked as failed although it was not used", errno)
		}
	}
}

func TestWriteWithGSOSendsThePacketsOneByOne(t *testing.T) {
	conn, raw := newScriptedSendConn(os.NewSyscallError("sendmsg", unix.EIO))
	if err := conn.Write(make([]byte, 10), 4, protocol.ECNUnsupported); err != nil {
		t.Fatalf("Write returned %v", err)
	}
	var sizes []int
	for _, w := range raw.writes[1:] {
		sizes = append(sizes, len(w))
	}
	if len(sizes) != 3 || sizes[0] != 4 || sizes[1] != 4 || sizes[2] != 2 {
		t.Fatalf("resent as %v, want [4 4 2]", sizes)
	}
	if !conn.gotGSOError {
		t.Fatal("GSO still enabled after a GSO error")
	}
}
