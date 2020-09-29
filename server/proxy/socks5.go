package proxy

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/astaxie/beego"
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
	hyAuthVersion   = uint8(128)
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

	localAddr := beego.AppConfig.String("nginx_ip_tcp")
	if "0.0.0.0:0" == localAddr || "" == localAddr {
		logs.Debug("no nginx use")
		localAddr = c.LocalAddr().String()
	}
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
	caddr, err := r.UDP(c, s.UdpReplayAddr)
	logs.Debug("===========client address is", caddr)
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
		logs.Debug("negotiation err", err)
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
	authVertion := beego.AppConfig.String("auth_version")
	switch authVertion {
	case "2":
		//用户密码验证方式
		buf[1] = UserPassAuth
		c.Write(buf)
		if err := s.Auth(c); err != nil {
			c.Close()
			logs.Warn("Validation failed:", err)
			return
		}
	case "128":
		//杭研院版本采用随机数验证方式，故此处不再返回2， 而是介于80-fe之间的随机数
		var challenge = Int2Byte(RandInt64())
		buf[1] = challenge[0]
		c.Write(buf)
		if err := s.hyAuth(c, challenge); err != nil {
			c.Close()
			logs.Warn("Validation failed:", err)
			return
		}
	default:
		buf[1] = 0
		c.Write(buf)
	}
	s.handleRequest(c)
}

//socks5 auth 杭研院版本验证方式
func (s *Sock5ModeServer) hyAuth(c net.Conn, challenge []byte) error {
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(c, header, 2); err != nil {
		return err
	}
	//杭研院版本验证方式
	if header[0] != userAuthVersion {
		return errors.New("验证方式不被支持")
	}
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(c, user, userLen); err != nil {
		return err
	}
	//获取到用户名
	username := string(user)
	if _, err := c.Read(header[:1]); err != nil {
		return errors.New("密码长度获取错误")
	}

	//获取 client端传送过来的hmac计算结果
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(c, pass, passLen); err != nil {
		return err
	}
	remoteHMAC := hex.EncodeToString(pass)
	//从数据库查询密码
	rdb, err := tool.GetRdb()
	if err != nil {
		_ = rdb.Close()
		return err
	}
	p, err := rdb.Get(username).Result()
	_ = rdb.Close()
	if err != nil {
		return errors.New("没有这个用户")
	}
	//根据随机数和拼接的用户名密码计算本地的验证码
	var message = username + p
	localHMAC := GenerateSign([]byte{challenge[0]}, []byte(message))
	//验证
	if localHMAC != "" && localHMAC == remoteHMAC {
		if _, err := c.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return err
		}
		return nil
	} else {
		if _, err := c.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return err
		}
		return errors.New(username + ":验证不通过" + localHMAC + "==" + remoteHMAC)
	}
}

/**
用户密码验证方式
*/
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
	//获取到用户名
	username := string(user)
	if _, err := c.Read(header[:1]); err != nil {
		return errors.New("密码长度获取错误")
	}

	//获取 client端传送过来的hmac计算结果
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(c, pass, passLen); err != nil {
		return err
	}
	password := string(pass)

	//从数据库查询密码
	rdb, err := tool.GetRdb()
	if err != nil {
		_ = rdb.Close()
		return err
	}
	p, err := rdb.Get(username).Result()
	_ = rdb.Close()
	if err != nil {
		return errors.New("验证不通过")
	}
	//验证
	if p != "" && p == password {
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
	return conn.NewTcpListenerAndProcess(beego.AppConfig.String("nginx_to_local_ip")+":"+strconv.Itoa(s.task.Port), func(c net.Conn) {
		if err := s.CheckFlowAndConnNum(s.task.Client); err != nil {
			logs.Warn("client id %d, task id %d, error %s, when socks5 connection", s.task.Client.Id, s.task.Id, err.Error())
			c.Close()
			return
		}
		logs.Debug("New socks5 connection,client %d,remote address %s", s.task.Client.Id, c.RemoteAddr())
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
	//从nginx来的用户流量需要先发送到这个ip由这个ip处理后 从另外一个可以通外网的ip出去 这个端口 最好固定 目前是tcp的端口加一 存在多个 tunnel时 需要注意不能重复或者冲突
	replyAddr, err := net.ResolveUDPAddr("udp", beego.AppConfig.String("nginx_to_local_ip")+":"+strconv.Itoa(s.task.Port+1))
	logs.Debug("replyAddr is", replyAddr)
	if err != nil {
		logs.Error("build local reply addr error", err)
		return err
	}
	//nginx需要转发数据到这个ip 端口上来（杭研院场景下是这样， 在其他场景下  应该是用户直接转发到这里来）
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
		//获取的addr应该为nginx 的地址（在杭研院的场景下， 在其他场景下应该是用户的地址）
		n, addr, err := s.UDPConn.ReadFromUDP(b)
		if err != nil {
			logs.Error("err", s.UDPConn, err)
			return err
		}
		//起一个协程处理这个请求
		go func(addr *net.UDPAddr, b []byte) {
			logs.Debug("=================RunUDPServer read begin")
			d, err := NewDatagramFromBytes(b)
			if err != nil {
				logs.Debug(err)
				return
			}
			if d.Frag != 0x00 {
				logs.Error("Ignore frag", d.Frag)
				return
			}
			logs.Debug("data is ", d)
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

		logs.Debug("Sent UDP data to remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), data)

		return nil
	}

	var ue *UDPExchange
	iue, ok := s.UDPExchanges.Get(addr.String())
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	logs.Debug("Call udp: %#v\n", d.Address())
	//使用连接外网的ip来进行数据转发。
	c, err := DialCustom("udp", d.Address(), beego.AppConfig.String("local_bridge_ip"))
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

	logs.Debug("Created remote UDP conn for client. client: %#v server: %#v remote: %#v\n", addr.String(), ue.RemoteConn.LocalAddr().String(), d.Address())

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

			logs.Debug("Got UDP data from remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), b[0:n])

			//转发给nginx,由nginx送给用户
			a, addr, port, err := ParseAddress(ue.ClientAddr.String())
			if err != nil {
				log.Println(err)
				break
			}
			d1 := NewDatagram(a, addr, port, b[0:n])
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
				break
			}

			logs.Debug("Sent Datagram. client: %#v server: %#v remote: %#v data: %#v %#v %#v %#v %#v %#v datagram address: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, d1.Data, d1.Address())

		}
	}(ue)
	return nil
}
