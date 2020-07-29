package proxy

import (
	"encoding/binary"
	"errors"
	"github.com/cnlh/nps/server/tool"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/astaxie/beego/logs"
	"github.com/cnlh/nps/lib/common"
	"github.com/cnlh/nps/lib/conn"
	"github.com/cnlh/nps/lib/file"
	cache "github.com/patrickmn/go-cache"
)

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn *net.UDPConn
}

const (
	ipV4            = 1
	domainName      = 3
	ipV6            = 4
	connectMethod   = 1
	bindMethod      = 2
	associateMethod = 3
	// The maximum packet size of any udp Associate packet, based on ethernet's max size,
	// minus the IP and UDP headers. IPv4 has a 20 byte header, UDP adds an
	// additional 4 bytes.  This is a total overhead of 24 bytes.  Ethernet's
	// max packet size is 1500 bytes,  1500 - 24 = 1476.
	maxUDPPacketSize = 1476
)

const (
	succeeded uint8 = iota
	serverFailure
	notAllowed
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

const (
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

type Sock5ModeServer struct {
	BaseServer
	SupportedCommands []byte
	listener          net.Listener
	TCPAddr           *net.TCPAddr
	UDPAddr           *net.UDPAddr
	ServerAddr        *net.UDPAddr
	UdpReplayAddr     *net.UDPAddr
	TCPListen         *net.TCPListener
	UDPConn           *net.UDPConn
	UDPExchanges      *cache.Cache
	TCPDeadline       int
	TCPTimeout        int
	UDPDeadline       int
	UDPSessionTime    int // If client does't send address, use this fixed time
	Handle            Handler
	TCPUDPAssociate   *cache.Cache
}
type Handler interface {
	// Request has not been replied yet
	handleUDP(*Sock5ModeServer, net.Conn, *Request)
	UDPHandle(*Sock5ModeServer, *net.UDPAddr, *Datagram) error
}
type DefaultHandle struct {
}

//req
func (s *Sock5ModeServer) handleRequest(c net.Conn) {
	/*
		The SOCKS request is formed as follows:
		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	*/
	r, err := s.GetRequest(c)
	if err != nil {
		logs.Info(err)
		return
	}
	s.Handle = &DefaultHandle{}
	switch r.Cmd {
	case connectMethod:
		s.handleConnect(c, r)
	case bindMethod:
		s.handleBind(c)
	case associateMethod:
		s.Handle.handleUDP(s, c, r)
	default:
		s.sendReply(c, commandNotSupported)
		c.Close()
	}
}

//reply
func (s *Sock5ModeServer) sendReply(c net.Conn, rep uint8) {
	reply := []byte{
		5,
		rep,
		0,
		1,
	}

	localAddr := c.LocalAddr().String()
	localHost, localPort, _ := net.SplitHostPort(localAddr)
	ipBytes := net.ParseIP(localHost).To4()
	nPort, _ := strconv.Atoi(localPort)
	reply = append(reply, ipBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(nPort))
	reply = append(reply, portBytes...)

	c.Write(reply)
}

//do conn
func (s *Sock5ModeServer) doConnect(c net.Conn, command uint8, r *Request) {
	addr := s.ToAddress(r.DstAddr, r.DstPort)
	var ltype string
	if command == associateMethod {
		ltype = common.CONN_UDP
	} else {
		ltype = common.CONN_TCP
	}
	s.DealClient(conn.NewConn(c), s.task.Client, addr, nil, ltype, func() {
		s.sendReply(c, succeeded)
	}, s.task.Flow, s.task.Target.LocalProxy)
	return
}

//conn
func (s *Sock5ModeServer) handleConnect(c net.Conn, r *Request) {
	s.doConnect(c, connectMethod, r)
}

// passive mode
func (s *Sock5ModeServer) handleBind(c net.Conn) {
}
func (s *Sock5ModeServer) sendUdpReply(writeConn net.Conn, c net.Conn, rep uint8, serverIp string) {
	reply := []byte{
		5,
		rep,
		0,
		1,
	}
	localHost, localPort, _ := net.SplitHostPort(c.LocalAddr().String())
	localHost = serverIp
	ipBytes := net.ParseIP(localHost).To4()
	nPort, _ := strconv.Atoi(localPort)
	reply = append(reply, ipBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(nPort))
	reply = append(reply, portBytes...)
	writeConn.Write(reply)

}

func (h *DefaultHandle) handleUDP(s *Sock5ModeServer, c net.Conn, r *Request) {
	logs.Info("server handleUDP begin")
	//replyAddr, err := net.ResolveUDPAddr("udp", "172.19.201.144"+":0")
	caddr, err := r.UDP(c, s.UdpReplayAddr)
	logs.Info("===========client address is", caddr)
	if err != nil {
		return
	}
	_, p, err := net.SplitHostPort(caddr.String())
	if err != nil {
		return
	}
	if p == "0" {
		time.Sleep(time.Duration(s.UDPSessionTime) * time.Second)
		return
	}
	ch := make(chan byte)
	s.TCPUDPAssociate.Set(caddr.String(), ch, cache.DefaultExpiration)
	<-ch
	return
}

//new conn
func (s *Sock5ModeServer) handleConn(c net.Conn) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		logs.Warn("negotiation err", err)
		c.Close()
		return
	}

	if version := buf[0]; version != 5 {
		logs.Warn("only support socks5, request from: ", c.RemoteAddr())
		c.Close()
		return
	}
	nMethods := buf[1]

	methods := make([]byte, nMethods)
	if len, err := c.Read(methods); len != int(nMethods) || err != nil {
		logs.Warn("wrong method")
		c.Close()
		return
	}
	buf[1] = UserPassAuth
	c.Write(buf)
	if err := s.Auth(c); err != nil {
		c.Close()
		logs.Warn("Validation failed:", err)
		return
	}
	s.handleRequest(c)
}

//socks5 auth
func (s *Sock5ModeServer) Auth(c net.Conn) error {
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(c, header, 2); err != nil {
		return err
	}
	if header[0] != userAuthVersion {
		return errors.New("验证方式不被支持")
	}
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(c, user, userLen); err != nil {
		return err
	}
	if _, err := c.Read(header[:1]); err != nil {
		return errors.New("密码长度获取错误")
	}
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(c, pass, passLen); err != nil {
		return err
	}
	var p string
	rdb := tool.GetRdb()
	if P := rdb.Get(string(user)); P != nil {
		p = P.String()
	}
	logs.Info("password is %s", p)
	if p != "" && string(pass) == p {
		if _, err := c.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return err
		}
		return nil
	} else {
		if _, err := c.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return err
		}
		return errors.New("验证不通过")
	}
}

//start
func (s *Sock5ModeServer) Start() error {
	s.TCPUDPAssociate = cache.New(cache.NoExpiration, cache.NoExpiration)
	s.UDPExchanges = cache.New(cache.NoExpiration, cache.NoExpiration)
	errch := make(chan error)
	go func() {
		errch <- s.RunUDPServer()
	}()
	return conn.NewTcpListenerAndProcess(s.task.ServerIp+":"+strconv.Itoa(s.task.Port), func(c net.Conn) {
		if err := s.CheckFlowAndConnNum(s.task.Client); err != nil {
			logs.Warn("client id %d, task id %d, error %s, when socks5 connection", s.task.Client.Id, s.task.Id, err.Error())
			c.Close()
			return
		}
		logs.Info("New socks5 connection,client %d,remote address %s", s.task.Client.Id, c.RemoteAddr())
		s.handleConn(c)
		s.task.Client.AddConn()
	}, &s.listener)
}

//new
func NewSock5ModeServer(bridge NetBridge, task *file.Tunnel) *Sock5ModeServer {
	s := new(Sock5ModeServer)
	s.bridge = bridge
	s.task = task
	return s
}

//close
func (s *Sock5ModeServer) Close() error {
	return s.listener.Close()
}

//start this udp server when main server start
func (s *Sock5ModeServer) RunUDPServer() error {
	replyAddr, err := net.ResolveUDPAddr("udp", s.GetHostAdd()+":0")
	logs.Info("replyAddr is", replyAddr)
	if err != nil {
		logs.Error("build local reply addr error", err)
		return err
	}
	s.UDPConn, err = net.ListenUDP("udp", replyAddr)
	if err != nil {
		logs.Error(err)
		return err
	}
	s.UdpReplayAddr, err = net.ResolveUDPAddr("udp", s.UDPConn.LocalAddr().String())
	if err != nil {
		logs.Error("build s.UdpReplayAddr error", err)
		return err
	}
	logs.Info("s.UDPConn address is", s.UDPConn.LocalAddr())
	defer s.UDPConn.Close()
	for {
		b := make([]byte, 65536)
		n, addr, err := s.UDPConn.ReadFromUDP(b)
		if err != nil {
			logs.Error("err", s.UDPConn, err)
			return err
		}
		go func(addr *net.UDPAddr, b []byte) {
			logs.Error("=================RunUDPServer read begin")
			d, err := NewDatagramFromBytes(b)
			if err != nil {
				logs.Error(err)
				return
			}
			if d.Frag != 0x00 {
				logs.Error("Ignore frag", d.Frag)
				return
			}
			logs.Info("data is ", d)
			if err := s.Handle.UDPHandle(s, addr, d); err != nil {
				logs.Error(err)
				return
			}
		}(addr, b[0:n])
	}
	return nil
}

// UDPHandle auto handle packet. You may prefer to do yourself.
func (h *DefaultHandle) UDPHandle(s *Sock5ModeServer, addr *net.UDPAddr, d *Datagram) error {
	send := func(ue *UDPExchange, data []byte) error {
		_, err := ue.RemoteConn.Write(data)
		if err != nil {
			return err
		}

		logs.Info("Sent UDP data to remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), data)

		return nil
	}

	var ue *UDPExchange
	iue, ok := s.UDPExchanges.Get(addr.String())
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	logs.Info("Call udp: %#v\n", d.Address())

	c, err := dial.Dial("udp", d.Address())
	if err != nil {
		v, ok := s.TCPUDPAssociate.Get(addr.String())
		if ok {
			ch := v.(chan byte)
			ch <- 0x00
			s.TCPUDPAssociate.Delete(addr.String())
		}
		return err
	}
	// A UDP association terminates when the TCP connection that the UDP
	// ASSOCIATE request arrived on terminates.
	rc := c.(*net.UDPConn)
	ue = &UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}

	logs.Info("Created remote UDP conn for client. client: %#v server: %#v remote: %#v\n", addr.String(), ue.RemoteConn.LocalAddr().String(), d.Address())

	if err := send(ue, d.Data); err != nil {
		v, ok := s.TCPUDPAssociate.Get(ue.ClientAddr.String())
		if ok {
			ch := v.(chan byte)
			ch <- 0x00
			s.TCPUDPAssociate.Delete(ue.ClientAddr.String())
		}
		ue.RemoteConn.Close()
		return err
	}
	s.UDPExchanges.Set(ue.ClientAddr.String(), ue, cache.DefaultExpiration)
	go func(ue *UDPExchange) {
		defer func() {
			v, ok := s.TCPUDPAssociate.Get(ue.ClientAddr.String())
			if ok {
				ch := v.(chan byte)
				ch <- 0x00
				s.TCPUDPAssociate.Delete(ue.ClientAddr.String())
			}
			s.UDPExchanges.Delete(ue.ClientAddr.String())
			ue.RemoteConn.Close()
		}()
		var b [65536]byte
		for {
			if s.UDPDeadline != 0 {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPDeadline) * time.Second)); err != nil {
					log.Println(err)
					break
				}
			}
			n, err := ue.RemoteConn.Read(b[:])
			if err != nil {
				break
			}

			logs.Info("Got UDP data from remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), b[0:n])

			a, addr, port, err := ParseAddress(ue.ClientAddr.String())
			if err != nil {
				log.Println(err)
				break
			}
			d1 := NewDatagram(a, addr, port, b[0:n])
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
				break
			}

			logs.Info("Sent Datagram. client: %#v server: %#v remote: %#v data: %#v %#v %#v %#v %#v %#v datagram address: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, d1.Data, d1.Address())

		}
	}(ue)
	return nil
}
