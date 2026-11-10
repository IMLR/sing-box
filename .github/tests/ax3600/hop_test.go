package ax3600_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/hysteria"
	M "github.com/sagernet/sing/common/metadata"
)

type packetTooBigOnce struct {
	net.Conn
	injected atomic.Bool
}

func (c *packetTooBigOnce) Read(p []byte) (int, error) {
	if !c.injected.Swap(true) {
		return 0, &net.OpError{Op: "read", Net: "udp", Err: syscall.EMSGSIZE}
	}
	return c.Conn.Read(p)
}

// A path-MTU notification must not permanently stop the active hop's receiver.
// The error is injected at the socket boundary; payloads use a real UDP socket.
func TestHopReceivesAfterPacketTooBig(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, address, readErr := server.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = server.WriteToUDP(buffer[:n], address)
		}
	}()
	address := M.ParseSocksaddr(server.LocalAddr().String())
	hop, err := hysteria.NewHopConn(func(destination M.Socksaddr) (net.Conn, error) {
		conn, dialErr := net.DialUDP("udp4", nil, destination.UDPAddr())
		if dialErr != nil {
			return nil, dialErr
		}
		return &packetTooBigOnce{Conn: conn}, nil
	}, address, []uint16{address.Port}, 5*time.Second, 6*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hop.Close() })
	want := []byte("port hopping still receives after EMSGSIZE")
	if _, err = hop.Write(want); err != nil {
		t.Fatal(err)
	}
	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, readErr := hop.Read(buffer)
		done <- result{buffer[:n], readErr}
	}()
	select {
	case got := <-done:
		if got.err != nil || !bytes.Equal(got.payload, want) {
			t.Fatalf("receive after EMSGSIZE: payload=%q error=%v", got.payload, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("port hopping receiver stopped after EMSGSIZE")
	}
}

// A real ICMP port unreachable, as a brief outage brings, reaches the active
// hop's connected socket as ECONNREFUSED from its next read. The socket still
// works once the path is back; a receiver that stopped there would leave the
// hop sending into a socket nobody reads until the next hop, minutes later.
func TestHopReceivesAfterUnreachable(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	address := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port))
	hop, err := hysteria.NewHopConn(func(destination M.Socksaddr) (net.Conn, error) {
		return net.DialUDP("udp4", nil, destination.UDPAddr())
	}, address, []uint16{address.Port}, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hop.Close() })
	// nothing listens yet: the kernel answers with port unreachable
	if _, err = hop.Write([]byte("into nothing")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, readErr := server.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = server.WriteToUDP(buffer[:n], from)
		}
	}()
	want := []byte("port hopping still receives after port unreachable")
	if _, err = hop.Write(want); err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, readErr := hop.Read(buffer)
		if readErr == nil {
			done <- buffer[:n]
		}
	}()
	select {
	case got := <-done:
		if !bytes.Equal(got, want) {
			t.Fatalf("received %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("port hopping receiver stopped after port unreachable")
	}
}

// closedQuietly reports a closed socket with an error of its own, as a wrapper
// might, instead of net.ErrClosed.
type closedQuietly struct {
	net.Conn
}

func (c *closedQuietly) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if errors.Is(err, net.ErrClosed) {
		return n, errors.New("socket gone")
	}
	return n, err
}

// The receiver of a socket replaced by a hop must end even when the closed
// socket does not report net.ErrClosed; otherwise every hop would leave one
// receiver retrying forever.
func TestHopReceiversEndAfterHops(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	address := M.ParseSocksaddr(server.LocalAddr().String())
	before := runtime.NumGoroutine()
	hop, err := hysteria.NewHopConn(func(destination M.Socksaddr) (net.Conn, error) {
		conn, dialErr := net.DialUDP("udp4", nil, destination.UDPAddr())
		if dialErr != nil {
			return nil, dialErr
		}
		return &closedQuietly{Conn: conn}, nil
	}, address, []uint16{address.Port}, 5*time.Second, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hop.Close() })
	// three hops: the first two sockets are closed, two receivers remain
	time.Sleep(15500 * time.Millisecond)
	if grown := runtime.NumGoroutine() - before; grown > 3 {
		t.Fatalf("%d goroutines more than before three hops; replaced receivers did not end", grown)
	}
}
