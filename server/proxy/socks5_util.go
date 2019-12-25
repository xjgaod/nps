package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	// Ver is socks protocol version
	Ver byte = 0x05

	// MethodNone is none method
	MethodNone byte = 0x00
	// MethodGSSAPI is gssapi method
	MethodGSSAPI byte = 0x01 // MUST support // todo
	// MethodUsernamePassword is username/assword auth method
	MethodUsernamePassword byte = 0x02 // SHOULD support
	// MethodUnsupportAll means unsupport all given methods
	MethodUnsupportAll byte = 0xFF

	// UserPassVer is username/password auth protocol version
	UserPassVer byte = 0x01
	// UserPassStatusSuccess is success status of username/password auth
	UserPassStatusSuccess byte = 0x00
	// UserPassStatusFailure is failure status of username/password auth
	UserPassStatusFailure byte = 0x01 // just other than 0x00

	// CmdConnect is connect command
	CmdConnect byte = 0x01
	// CmdBind is bind command
	CmdBind byte = 0x02
	// CmdUDP is UDP command
	CmdUDP byte = 0x03

	// ATYPIPv4 is ipv4 address type
	ATYPIPv4 byte = 0x01 // 4 octets
	// ATYPDomain is domain address type
	ATYPDomain byte = 0x03 // The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.
	// ATYPIPv6 is ipv6 address type
	ATYPIPv6 byte = 0x04 // 16 octets

	// RepSuccess means that success for repling
	RepSuccess byte = 0x00
	// RepServerFailure means the server failure
	RepServerFailure byte = 0x01
	// RepNotAllowed means the request not allowed
	RepNotAllowed byte = 0x02
	// RepNetworkUnreachable means the network unreachable
	RepNetworkUnreachable byte = 0x03
	// RepHostUnreachable means the host unreachable
	RepHostUnreachable byte = 0x04
	// RepConnectionRefused means the connection refused
	RepConnectionRefused byte = 0x05
	// RepTTLExpired means the TTL expired
	RepTTLExpired byte = 0x06
	// RepCommandNotSupported means the request command not supported
	RepCommandNotSupported byte = 0x07
	// RepAddressNotSupported means the request address not supported
	RepAddressNotSupported byte = 0x08
)

type NegotiationRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1-255 bytes
}

// NegotiationReply is the negotiation reply packet
type NegotiationReply struct {
	Ver    byte
	Method byte
}

// UserPassNegotiationRequest is the negotiation username/password reqeust packet
type UserPassNegotiationRequest struct {
	Ver    byte
	Ulen   byte
	Uname  []byte // 1-255 bytes
	Plen   byte
	Passwd []byte // 1-255 bytes
}

// UserPassNegotiationReply is the negotiation username/password reply packet
type UserPassNegotiationReply struct {
	Ver    byte
	Status byte
}

// Request is the request packet
type Request struct {
	Ver     byte
	Cmd     byte
	Rsv     byte // 0x00
	Atyp    byte
	DstAddr []byte
	DstPort []byte // 2 bytes
}

// Reply is the reply packet
type Reply struct {
	Ver  byte
	Rep  byte
	Rsv  byte // 0x00
	Atyp byte
	// CONNECT socks server's address which used to connect to dst addr
	// BIND ...
	// UDP socks server's address which used to connect to dst addr
	BndAddr []byte
	// CONNECT socks server's port which used to connect to dst addr
	// BIND ...
	// UDP socks server's port which used to connect to dst addr
	BndPort []byte // 2 bytes
}

// Datagram is the UDP packet
type Datagram struct {
	Rsv     []byte // 0x00 0x00
	Frag    byte
	Atyp    byte
	DstAddr []byte
	DstPort []byte // 2 bytes
	Data    []byte
}

var (
	// ErrVersion is version error
	ErrVersion = errors.New("Invalid Version")
	// ErrUserPassVersion is username/password auth version error
	ErrUserPassVersion = errors.New("Invalid Version of Username Password Auth")
	// ErrBadRequest is bad request error
	ErrBadRequest = errors.New("Bad Request")

	dial Dialer = DefaultDial

	// ErrUnsupportCmd is the error when got unsupport command
	ErrUnsupportCmd = errors.New("Unsupport Command")
)

func NewDatagramFromBytes(bb []byte) (*Datagram, error) {
	n := len(bb)
	minl := 4
	if n < minl {
		return nil, ErrBadRequest
	}
	var addr []byte
	if bb[3] == ATYPIPv4 {
		minl += 4
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-4 : minl]
	} else if bb[3] == ATYPIPv6 {
		minl += 16
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-16 : minl]
	} else if bb[3] == ATYPDomain {
		minl += 1
		if n < minl {
			return nil, ErrBadRequest
		}
		l := bb[4]
		if l == 0 {
			return nil, ErrBadRequest
		}
		minl += int(l)
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-int(l) : minl]
		addr = append([]byte{l}, addr...)
	} else {
		return nil, ErrBadRequest
	}
	minl += 2
	if n <= minl {
		return nil, ErrBadRequest
	}
	port := bb[minl-2 : minl]
	data := bb[minl:]
	d := &Datagram{
		Rsv:     bb[0:2],
		Frag:    bb[2],
		Atyp:    bb[3],
		DstAddr: addr,
		DstPort: port,
		Data:    data,
	}
	//	if Debug {
	//		log.Printf("Got Datagram. data: %#v %#v %#v %#v %#v %#v datagram address: %#v\n", d.Rsv, d.Frag, d.Atyp, d.DstAddr, d.DstPort, d.Data, d.Address())
	//	}
	return d, nil
}
func (d *Datagram) Address() string {
	var s string
	if d.Atyp == ATYPDomain {
		s = bytes.NewBuffer(d.DstAddr[1:]).String()
	} else {
		s = net.IP(d.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(d.DstPort)))
	return net.JoinHostPort(s, p)
}

func ParseAddress(address string) (a byte, addr []byte, port []byte, err error) {
	var h, p string
	h, p, err = net.SplitHostPort(address)
	if err != nil {
		return
	}
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		a = ATYPIPv4
		addr = []byte(ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		a = ATYPIPv6
		addr = []byte(ip6)
	} else {
		a = ATYPDomain
		addr = []byte{byte(len(h))}
		addr = append(addr, []byte(h)...)
	}
	i, _ := strconv.Atoi(p)
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(i))
	return
}

func NewDatagram(atyp byte, dstaddr []byte, dstport []byte, data []byte) *Datagram {
	if atyp == ATYPDomain {
		dstaddr = append([]byte{byte(len(dstaddr))}, dstaddr...)
	}
	return &Datagram{
		Rsv:     []byte{0x00, 0x00},
		Frag:    0x00,
		Atyp:    atyp,
		DstAddr: dstaddr,
		DstPort: dstport,
		Data:    data,
	}
}
func (d *Datagram) Bytes() []byte {
	b := make([]byte, 0)
	b = append(b, d.Rsv...)
	b = append(b, d.Frag)
	b = append(b, d.Atyp)
	b = append(b, d.DstAddr...)
	b = append(b, d.DstPort...)
	b = append(b, d.Data...)
	return b
}

func (r *Request) UDP(c net.Conn, serverAddr *net.UDPAddr) (*net.UDPAddr, error) {
	clientAddr, err := net.ResolveUDPAddr("udp", r.Address())
	if err != nil {
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepHostUnreachable, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepHostUnreachable, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if err := p.WriteTo(c); err != nil {
			return nil, err
		}
		return nil, err
	}
	//	if Debug {
	//		log.Println("Client wants to start UDP talk use", clientAddr.String())
	//	}
	a, addr, port, err := ParseAddress(serverAddr.String())
	if err != nil {
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepHostUnreachable, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepHostUnreachable, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if err := p.WriteTo(c); err != nil {
			return nil, err
		}
		return nil, err
	}
	p := NewReply(RepSuccess, a, addr, port)
	if err := p.WriteTo(c); err != nil {
		return nil, err
	}

	return clientAddr, nil
}

func (r *Request) Address() string {
	var s string
	if r.Atyp == ATYPDomain {
		s = bytes.NewBuffer(r.DstAddr[1:]).String()
	} else {
		s = net.IP(r.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.DstPort)))
	return net.JoinHostPort(s, p)
}

func NewReply(rep byte, atyp byte, bndaddr []byte, bndport []byte) *Reply {
	if atyp == ATYPDomain {
		bndaddr = append([]byte{byte(len(bndaddr))}, bndaddr...)
	}
	return &Reply{
		Ver:     Ver,
		Rep:     rep,
		Rsv:     0x00,
		Atyp:    atyp,
		BndAddr: bndaddr,
		BndPort: bndport,
	}
}
func (r *Reply) WriteTo(w net.Conn) error {
	if _, err := w.Write([]byte{r.Ver, r.Rep, r.Rsv, r.Atyp}); err != nil {
		return err
	}
	if _, err := w.Write(r.BndAddr); err != nil {
		return err
	}
	if _, err := w.Write(r.BndPort); err != nil {
		return err
	}
	//	if Debug {
	//		log.Printf("Sent Reply: %#v %#v %#v %#v %#v %#v\n", r.Ver, r.Rep, r.Rsv, r.Atyp, r.BndAddr, r.BndPort)
	//	}
	return nil
}
func (s *Sock5ModeServer) GetRequest(c net.Conn) (*Request, error) {
	r, err := NewRequestFrom(c)
	if err != nil {
		return nil, err
	}
	var supported bool

	if r.Cmd == CmdConnect || r.Cmd == CmdUDP {
		supported = true
	}

	if !supported {
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepCommandNotSupported, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepCommandNotSupported, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if err := p.WriteTo(c); err != nil {
			return nil, err
		}
		return nil, ErrUnsupportCmd
	}
	return r, nil
}

func NewRequestFrom(r net.Conn) (*Request, error) {
	bb := make([]byte, 4)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}
	var addr []byte
	if bb[3] == ATYPIPv4 {
		addr = make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	} else if bb[3] == ATYPIPv6 {
		addr = make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	} else if bb[3] == ATYPDomain {
		dal := make([]byte, 1)
		if _, err := io.ReadFull(r, dal); err != nil {
			return nil, err
		}
		if dal[0] == 0 {
			return nil, ErrBadRequest
		}
		addr = make([]byte, int(dal[0]))
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		addr = append(dal, addr...)
	} else {
		return nil, ErrBadRequest
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	//	if Debug {
	//		log.Printf("Got Request: %#v %#v %#v %#v %#v %#v\n", bb[0], bb[1], bb[2], bb[3], addr, port)
	//	}
	return &Request{
		Ver:     bb[0],
		Cmd:     bb[1],
		Rsv:     bb[2],
		Atyp:    bb[3],
		DstAddr: addr,
		DstPort: port,
	}, nil
}
