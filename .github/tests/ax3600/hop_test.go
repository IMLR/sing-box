package ax3600_test

import (
	"bytes"
	"net"
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
