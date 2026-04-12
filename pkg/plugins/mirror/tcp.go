package mirror

import (
	"fmt"
	"io"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/qpoint-io/qtap/pkg/qnet"
)

const (
	FakeMACSrcSrc = "02:00:00:00:00:01"
	FakeMACDstSrc = "02:00:00:00:00:02"

	ChunkSize = 1400
)

var (
	FakeMACSrc = parseMAC(FakeMACSrcSrc)
	FakeMACDst = parseMAC(FakeMACDstSrc)
)

// TCPMirror builds and serializes Ethernet/IP/TCP packets and writes them
// to an io.Writer.
type TCPMirror struct {
	w io.Writer

	// next sequence numbers for source and destination directions
	srcSeq uint32
	dstSeq uint32
}

func NewTCPMirror(w io.Writer, srcSeq, dstSeq uint32) *TCPMirror {
	return &TCPMirror{w: w, srcSeq: srcSeq, dstSeq: dstSeq}
}

func (t *TCPMirror) SendFromSrc(src, dst qnet.NetAddr, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}

	for i := 0; i < len(payload); i += ChunkSize {
		end := min(i+ChunkSize, len(payload))
		chunk := payload[i:end]

		if err := t.writePacket(src, dst, t.srcSeq, t.dstSeq, chunk); err != nil {
			return err
		}

		n := uint32(len(chunk))
		t.srcSeq += n
	}

	return nil
}

func (t *TCPMirror) SendFromDst(src, dst qnet.NetAddr, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}

	for i := 0; i < len(payload); i += ChunkSize {
		end := min(i+ChunkSize, len(payload))
		chunk := payload[i:end]

		if err := t.writePacket(src, dst, t.dstSeq, t.srcSeq, chunk); err != nil {
			return err
		}

		n := uint32(len(chunk))
		t.dstSeq += n
	}

	return nil
}

func (t *TCPMirror) writePacket(src, dst qnet.NetAddr, seq, ack uint32, payload []byte) error {
	if t.w == nil {
		return fmt.Errorf("tcpmirror: no writer configured")
	}

	b, err := t.buildPacket(src, dst, seq, ack, payload)
	if err != nil {
		return err
	}

	_, err = t.w.Write(b)
	return err
}

func (t *TCPMirror) buildPacket(src, dst qnet.NetAddr, seq, ack uint32, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC: FakeMACSrc,
		DstMAC: FakeMACDst,
	}

	var ipLayer gopacket.NetworkLayer
	var tcpParent gopacket.SerializableLayer

	// Decide between IPv4 and IPv6. Prefer explicit family if provided,
	// otherwise fall back to checking whether the address has a v4 representation.
	if src.Family == qnet.NetFamily_IPv4 {
		eth.EthernetType = layers.EthernetTypeIPv4
		ipv4 := &layers.IPv4{
			SrcIP:    src.IP.To4(),
			DstIP:    dst.IP.To4(),
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		ipLayer = ipv4
		tcpParent = ipv4
	} else {
		// If the address contains an IPv4-mapped address, prefer IPv4 on the wire.
		if src.IP.To4() != nil {
			eth.EthernetType = layers.EthernetTypeIPv4
			ipv4 := &layers.IPv4{
				SrcIP:    src.IP.To4(),
				DstIP:    dst.IP.To4(),
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
			}
			ipLayer = ipv4
			tcpParent = ipv4
		} else {
			eth.EthernetType = layers.EthernetTypeIPv6
			ipv6 := &layers.IPv6{
				SrcIP:      src.IP.To16(),
				DstIP:      dst.IP.To16(),
				Version:    6,
				HopLimit:   64,
				NextHeader: layers.IPProtocolTCP,
			}
			ipLayer = ipv6
			tcpParent = ipv6
		}
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(src.Port),
		DstPort: layers.TCPPort(dst.Port),
		Seq:     seq,
		Ack:     ack,
		ACK:     true,
		PSH:     true,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	layersToSerialize := []gopacket.SerializableLayer{eth, tcpParent, tcp, gopacket.Payload(payload)}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func parseMAC(macStr string) net.HardwareAddr {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		panic(fmt.Sprintf("invalid MAC address: %s", macStr))
	}
	return mac
}
