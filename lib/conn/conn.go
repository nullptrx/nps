package conn

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/goroutine"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/pmux"
	"github.com/djylb/nps/lib/rate"
	"github.com/xtaci/kcp-go/v5"
)

var LocalTCPAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}

type Conn struct {
	Conn net.Conn
	Rb   []byte
	wBuf *bytes.Buffer
	mu   sync.Mutex
}

// new conn
func NewConn(conn net.Conn) *Conn {
	return &Conn{
		Conn: conn,
		wBuf: new(bytes.Buffer),
	}
}

func NewConnWithRb(conn net.Conn, rb []byte) *Conn {
	return &Conn{
		Conn: conn,
		Rb:   rb,
		wBuf: new(bytes.Buffer),
	}
}

func (s *Conn) readRequest(buf []byte) (n int, err error) {
	var rd int
	for {
		rd, err = s.Read(buf[n:])
		if err != nil {
			return
		}
		n += rd
		if n < 4 {
			continue
		}
		if string(buf[n-4:n]) == "\r\n\r\n" {
			return
		}
		// buf is full, can't contain the request
		if n == cap(buf) {
			err = io.ErrUnexpectedEOF
			return
		}
	}
}

// get host 、connection type、method...from connection
func (s *Conn) GetHost() (method, address string, rb []byte, err error, r *http.Request) {
	var b [32 * 1024]byte
	var n int
	if n, err = s.readRequest(b[:]); err != nil {
		return
	}
	rb = b[:n]
	r, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(rb)))
	if err != nil {
		return
	}
	hostPortURL, err := url.Parse(r.Host)
	if err != nil {
		address = r.Host
		err = nil
		return
	}
	if hostPortURL.Opaque == "443" {
		if strings.Index(r.Host, ":") == -1 {
			address = r.Host + ":443"
		} else {
			address = r.Host
		}
	} else {
		if strings.Index(r.Host, ":") == -1 {
			address = r.Host + ":80"
		} else {
			address = r.Host
		}
	}
	return
}

func (s *Conn) GetShortLenContent() (b []byte, err error) {
	var l int
	if l, err = s.GetLen(); err != nil {
		return
	}
	if l < 0 || l > 32<<10 {
		err = errors.New("read length error")
		return
	}
	return s.GetShortContent(l)
}

func (s *Conn) GetShortContent(l int) (b []byte, err error) {
	buf := make([]byte, l)
	return buf, binary.Read(s, binary.LittleEndian, &buf)
}

func (s *Conn) ReadLen(cLen int, buf []byte) (int, error) {
	if cLen > len(buf) || cLen <= 0 {
		return 0, errors.New("invalid length: " + strconv.Itoa(cLen))
	}
	n, err := io.ReadFull(s, buf[:cLen])
	if err != nil || n != cLen {
		return n, fmt.Errorf("error reading %d bytes: %w", cLen, err)
	}
	return cLen, nil
}

func (s *Conn) GetLen() (int, error) {
	var l int32
	err := binary.Read(s, binary.LittleEndian, &l)
	return int(l), err
}

func (s *Conn) WriteLenContent(buf []byte) (err error) {
	var b []byte
	if b, err = GetLenBytes(buf); err != nil {
		return
	}
	//return binary.Write(s.Conn, binary.LittleEndian, b)
	_, err = s.BufferWrite(b)
	return
}

// read flag
func (s *Conn) ReadFlag() (string, error) {
	buf := make([]byte, 4)
	return string(buf), binary.Read(s, binary.LittleEndian, &buf)
}

// set alive
func (s *Conn) SetAlive() {
	switch s.Conn.(type) {
	case *kcp.UDPSession:
		_ = s.Conn.(*kcp.UDPSession).SetReadDeadline(time.Time{})
	case *net.TCPConn:
		_ = s.Conn.(*net.TCPConn).SetReadDeadline(time.Time{})
	case *pmux.PortConn:
		_ = s.Conn.(*pmux.PortConn).SetReadDeadline(time.Time{})
	case *tls.Conn:
		_ = s.Conn.(*tls.Conn).SetReadDeadline(time.Time{})
	case *TlsConn:
		_ = s.Conn.(*TlsConn).SetReadDeadline(time.Time{})
	default:
		if conn, ok := s.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = conn.SetReadDeadline(time.Time{})
		}
	}
}

// set read deadline
func (s *Conn) SetReadDeadlineBySecond(t time.Duration) {
	switch s.Conn.(type) {
	case *kcp.UDPSession:
		_ = s.Conn.(*kcp.UDPSession).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	case *net.TCPConn:
		_ = s.Conn.(*net.TCPConn).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	case *pmux.PortConn:
		_ = s.Conn.(*pmux.PortConn).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	case *tls.Conn:
		_ = s.Conn.(*tls.Conn).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	case *TlsConn:
		_ = s.Conn.(*TlsConn).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	default:
		if conn, ok := s.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = conn.SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
		}
	}
}

// get link info from conn
func (s *Conn) GetLinkInfo() (lk *Link, err error) {
	err = s.getInfo(&lk)
	return
}

// send info for link
func (s *Conn) SendHealthInfo(info, status string) (int, error) {
	raw := bytes.NewBuffer([]byte{})
	common.BinaryWrite(raw, info, status)
	return s.Write(raw.Bytes())
}

// get health info from conn
func (s *Conn) GetHealthInfo(timeout time.Duration) (info string, status bool, err error) {
	_ = s.SetReadDeadline(time.Now().Add(timeout))
	defer s.SetReadDeadline(time.Time{})
	var l int
	l, err = s.GetLen()
	if err != nil {
		return
	}
	buf := common.BufPoolMax.Get().([]byte)
	defer common.PutBufPoolMax(buf)
	_, err = s.ReadLen(l, buf)
	if err != nil {
		return
	}
	arr := strings.Split(string(buf[:l]), common.CONN_DATA_SEQ)
	if len(arr) < 2 {
		return "", false, errors.New("receive health info error")
	}
	return arr[0], common.GetBoolByStr(arr[1]), nil
}

// get task info
func (s *Conn) GetHostInfo() (h *file.Host, err error) {
	err = s.getInfo(&h)
	h.Id = int(file.GetDb().JsonDb.GetHostId())
	h.Flow = new(file.Flow)
	h.NoStore = true
	return
}

// get task info
func (s *Conn) GetConfigInfo() (c *file.Client, err error) {
	err = s.getInfo(&c)
	c.NoStore = true
	c.Status = true
	if c.Flow == nil {
		c.Flow = new(file.Flow)
	}
	c.NoDisplay = false
	return
}

// get task info
func (s *Conn) GetTaskInfo() (t *file.Tunnel, err error) {
	err = s.getInfo(&t)
	t.Id = int(file.GetDb().JsonDb.GetTaskId())
	t.NoStore = true
	t.Flow = new(file.Flow)
	return
}

// send  info
func (s *Conn) SendInfo(t interface{}, flag string) (int, error) {
	/*
		The task info is formed as follows:
		+----+-----+---------+
		|type| len | content |
		+----+---------------+
		| 4  |  4  |   ...   |
		+----+---------------+
	*/
	raw := bytes.NewBuffer([]byte{})
	if flag != "" {
		_ = binary.Write(raw, binary.LittleEndian, []byte(flag))
	}
	b, err := json.Marshal(t)
	if err != nil {
		return 0, err
	}
	lenBytes, err := GetLenBytes(b)
	if err != nil {
		return 0, err
	}
	_ = binary.Write(raw, binary.LittleEndian, lenBytes)
	return s.Write(raw.Bytes())
}

// get task info
func (s *Conn) getInfo(t interface{}) (err error) {
	var l int
	buf := common.BufPoolMax.Get().([]byte)
	defer common.PutBufPoolMax(buf)
	if l, err = s.GetLen(); err != nil {
		return
	} else if _, err = s.ReadLen(l, buf); err != nil {
		return
	} else {
		_ = json.Unmarshal(buf[:l], &t)
	}
	return
}

// close
func (s *Conn) Close() error {
	return s.Conn.Close()
}

// write
func (s *Conn) Write(b []byte) (n int, err error) {
	if s == nil {
		return -1, errors.New("connection error")
	}

	s.mu.Lock()
	if s.wBuf.Len() == 0 {
		s.mu.Unlock()
		return s.Conn.Write(b)
	}
	n, err = s.wBuf.Write(b)
	toSend := s.wBuf.Bytes()
	s.wBuf.Reset()
	defer s.mu.Unlock()

	if _, err := s.Conn.Write(toSend); err != nil {
		return 0, err
	}

	return
}

func (s *Conn) BufferWrite(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wBuf.Write(b)
}

func (s *Conn) FlushBuf() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wBuf.Len() == 0 {
		return nil
	}
	_, err := s.Conn.Write(s.wBuf.Bytes())
	s.wBuf.Reset()
	return err
}

// read
func (s *Conn) Read(b []byte) (n int, err error) {
	if err = s.FlushBuf(); err != nil {
		return 0, err
	}

	if s.Rb != nil {
		//if the rb is not nil ,read rb first
		if len(s.Rb) > 0 {
			n = copy(b, s.Rb)
			s.Rb = s.Rb[n:]
			return
		}
		s.Rb = nil
	}
	return s.Conn.Read(b)
}

// write sign flag
func (s *Conn) WriteClose() (int, error) {
	return s.Write([]byte(common.RES_CLOSE))
}

// write main
func (s *Conn) WriteMain() (int, error) {
	return s.Write([]byte(common.WORK_MAIN))
}

// write main
func (s *Conn) WriteConfig() (int, error) {
	return s.Write([]byte(common.WORK_CONFIG))
}

// write chan
func (s *Conn) WriteChan() (int, error) {
	return s.Write([]byte(common.WORK_CHAN))
}

// get task or host result of add
func (s *Conn) GetAddStatus() (b bool) {
	_ = binary.Read(s, binary.LittleEndian, &b)
	return
}

func (s *Conn) WriteAddOk() error {
	return binary.Write(s, binary.LittleEndian, true)
}

func (s *Conn) WriteAddFail() error {
	defer s.Close()
	return binary.Write(s, binary.LittleEndian, false)
}

func (s *Conn) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *Conn) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s *Conn) SetDeadline(t time.Time) error {
	return s.Conn.SetDeadline(t)
}

func (s *Conn) SetWriteDeadline(t time.Time) error {
	return s.Conn.SetWriteDeadline(t)
}

func (s *Conn) SetReadDeadline(t time.Time) error {
	return s.Conn.SetReadDeadline(t)
}

// get the assembled amount data(len 4 and content)
func GetLenBytes(buf []byte) (b []byte, err error) {
	raw := bytes.NewBuffer([]byte{})
	if err = binary.Write(raw, binary.LittleEndian, int32(len(buf))); err != nil {
		return
	}
	if err = binary.Write(raw, binary.LittleEndian, buf); err != nil {
		return
	}
	b = raw.Bytes()
	return
}

// udp connection setting
func SetUdpSession(sess *kcp.UDPSession) {
	sess.SetStreamMode(true)
	sess.SetWindowSize(1024, 1024)
	_ = sess.SetReadBuffer(64 * 1024)
	_ = sess.SetWriteBuffer(64 * 1024)
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetMtu(1600)
	sess.SetACKNoDelay(true)
	sess.SetWriteDelay(false)
}

// conn1 mux conn
func CopyWaitGroup(conn1, conn2 net.Conn, crypt bool, snappy bool, rate *rate.Rate,
	flows []*file.Flow, isServer bool, proxyProtocol int, rb []byte, task *file.Tunnel) {
	connHandle := GetConn(conn1, crypt, snappy, rate, isServer)
	proxyHeader := BuildProxyProtocolHeader(conn2, proxyProtocol)
	if proxyHeader != nil {
		logs.Debug("Sending Proxy Protocol v%d header to backend: %v", proxyProtocol, proxyHeader)
		_, _ = connHandle.Write(proxyHeader)
	}
	if rb != nil {
		_, _ = connHandle.Write(rb)
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := goroutine.CopyConnsPool.Invoke(goroutine.NewConns(connHandle, conn2, flows, wg, task))
	if err != nil {
		logs.Error("CopyConnsPool.Invoke failed: %v", err)
		wg.Done()
		connHandle.Close()
		conn2.Close()
	}
	wg.Wait()
}

// 构造 Proxy-Protocol v1 头 (TCP / UDP)
func BuildProxyProtocolV1Header(clientAddr, targetAddr net.Addr) []byte {
	var (
		protocol           = "UNKNOWN"
		clientIP, targetIP string
		srcPort, dstPort   int
	)

	switch c := clientAddr.(type) {
	case *net.TCPAddr:
		if t, ok := targetAddr.(*net.TCPAddr); ok {
			clientIP, targetIP = c.IP.String(), t.IP.String()
			srcPort, dstPort = c.Port, t.Port
			if c.IP.To4() != nil {
				protocol = "TCP4"
			} else {
				protocol = "TCP6"
			}
		}
	case *net.UDPAddr:
		if u, ok := targetAddr.(*net.UDPAddr); ok {
			clientIP, targetIP = c.IP.String(), u.IP.String()
			srcPort, dstPort = c.Port, u.Port
			if c.IP.To4() != nil {
				protocol = "TCP4"
			} else {
				protocol = "TCP6"
			}
		}
	}

	if protocol == "UNKNOWN" {
		return []byte("PROXY UNKNOWN\r\n")
	}

	header := "PROXY " + protocol + " " + clientIP + " " + targetIP + " " +
		strconv.Itoa(srcPort) + " " + strconv.Itoa(dstPort) + "\r\n"
	return []byte(header)
}

// 构造 Proxy-Protocol v2 头 (TCP / UDP)
func BuildProxyProtocolV2Header(clientAddr, targetAddr net.Addr) []byte {
	const sig = "\r\n\r\n\000\r\nQUIT\n" // 12-byte v2 signature
	var (
		header           []byte
		famProto         byte
		addrBytes        uint16
		srcIP, dstIP     net.IP
		srcPort, dstPort uint16
	)

	switch c := clientAddr.(type) {
	case *net.TCPAddr:
		t := targetAddr.(*net.TCPAddr)
		srcIP, dstIP = c.IP, t.IP
		srcPort, dstPort = uint16(c.Port), uint16(t.Port)
		if c.IP.To4() != nil {
			famProto, addrBytes = 0x11, 12 // TCPv4
		} else {
			famProto, addrBytes = 0x21, 36 // TCPv6
		}
	case *net.UDPAddr:
		u := targetAddr.(*net.UDPAddr)
		srcIP, dstIP = c.IP, u.IP
		srcPort, dstPort = uint16(c.Port), uint16(u.Port)
		if c.IP.To4() != nil {
			famProto, addrBytes = 0x12, 12 // UDPv4
		} else {
			famProto, addrBytes = 0x22, 36 // UDPv6
		}
	}

	header = make([]byte, 16+addrBytes)
	copy(header[:12], sig)
	header[12] = 0x21 // v2 + PROXY
	header[13] = famProto
	binary.BigEndian.PutUint16(header[14:16], addrBytes)

	if addrBytes == 12 { // IPv4
		copy(header[16:20], srcIP.To4())
		copy(header[20:24], dstIP.To4())
		binary.BigEndian.PutUint16(header[24:26], srcPort)
		binary.BigEndian.PutUint16(header[26:28], dstPort)
	} else { // IPv6
		copy(header[16:32], srcIP.To16())
		copy(header[32:48], dstIP.To16())
		binary.BigEndian.PutUint16(header[48:50], srcPort)
		binary.BigEndian.PutUint16(header[50:52], dstPort)
	}
	return header
}

// 构造 Proxy Protocol 头部
func BuildProxyProtocolHeader(c net.Conn, proxyProtocol int) []byte {
	if proxyProtocol == 0 {
		return nil
	}
	clientAddr := c.RemoteAddr()
	targetAddr := c.LocalAddr()

	if proxyProtocol == 2 {
		return BuildProxyProtocolV2Header(clientAddr, targetAddr)
	}
	if proxyProtocol == 1 {
		return BuildProxyProtocolV1Header(clientAddr, targetAddr)
	}
	return nil
}

func BuildProxyProtocolHeaderByAddr(clientAddr, targetAddr net.Addr, proxyProtocol int) []byte {
	if proxyProtocol == 0 {
		return nil
	}

	targetAddr = normalizeTarget(clientAddr, targetAddr)

	switch proxyProtocol {
	case 2:
		return BuildProxyProtocolV2Header(clientAddr, targetAddr)
	case 1:
		return BuildProxyProtocolV1Header(clientAddr, targetAddr)
	default:
		return nil
	}
}

func normalizeTarget(src, dst net.Addr) net.Addr {
	switch s := src.(type) {

	// TCP
	case *net.TCPAddr:
		d, _ := dst.(*net.TCPAddr)
		if d == nil {
			d = &net.TCPAddr{Port: 0}
		}
		srcIsV4 := s.IP.To4() != nil
		dstIsV4 := d.IP != nil && d.IP.To4() != nil

		switch {
		case srcIsV4 && !dstIsV4:
			d.IP = net.IPv4zero
		case !srcIsV4 && dstIsV4:
			d.IP = append(net.IPv6zero[:12], d.IP.To4()...)
		case d.IP == nil || d.IP.IsUnspecified():
			if srcIsV4 {
				d.IP = net.IPv4zero
			} else {
				d.IP = net.IPv6zero
			}
		}
		return d

	// UDP
	case *net.UDPAddr:
		d, _ := dst.(*net.UDPAddr)
		if d == nil {
			d = &net.UDPAddr{Port: 0}
		}
		srcIsV4 := s.IP.To4() != nil
		dstIsV4 := d.IP != nil && d.IP.To4() != nil

		switch {
		case srcIsV4 && !dstIsV4:
			d.IP = net.IPv4zero
		case !srcIsV4 && dstIsV4:
			d.IP = append(net.IPv6zero[:12], d.IP.To4()...)
		case d.IP == nil || d.IP.IsUnspecified():
			if srcIsV4 {
				d.IP = net.IPv4zero
			} else {
				d.IP = net.IPv6zero
			}
		}
		return d

	// Other
	default:
		return dst
	}
}

// get crypt or snappy conn
func GetConn(conn net.Conn, cpt, snappy bool, rt *rate.Rate, isServer bool) io.ReadWriteCloser {
	if cpt {
		if isServer {
			return rate.NewRateConn(crypt.NewTlsServerConn(conn), rt)
		}
		return rate.NewRateConn(crypt.NewTlsClientConn(conn), rt)
	} else if snappy {
		return rate.NewRateConn(NewSnappyConn(conn), rt)
	}
	return rate.NewRateConn(conn, rt)
}

type LenConn struct {
	conn io.Writer
	Len  int
}

func NewLenConn(conn io.Writer) *LenConn {
	return &LenConn{conn: conn}
}

func (c *LenConn) Write(p []byte) (n int, err error) {
	n, err = c.conn.Write(p)
	c.Len += n
	return
}

type RWConn struct {
	io.ReadWriteCloser
	FakeAddr net.Addr
}

func NewRWConn(conn io.ReadWriteCloser) *RWConn {
	return &RWConn{
		ReadWriteCloser: conn,
		FakeAddr:        LocalTCPAddr,
	}
}

func (c *RWConn) LocalAddr() net.Addr                { return c.FakeAddr }
func (c *RWConn) RemoteAddr() net.Addr               { return c.FakeAddr }
func (c *RWConn) SetDeadline(t time.Time) error      { return nil }
func (c *RWConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *RWConn) SetWriteDeadline(t time.Time) error { return nil }

type FlowConn struct {
	*RWConn
	taskFlow   *file.Flow
	clientFlow *file.Flow
}

func NewFlowConn(conn io.ReadWriteCloser, task, client *file.Flow) *FlowConn {
	return &FlowConn{
		RWConn:     NewRWConn(conn),
		taskFlow:   task,
		clientFlow: client,
	}
}

func CheckFlowLimits(f *file.Flow, label string, now time.Time) error {
	if f.FlowLimit > 0 && (f.InletFlow+f.ExportFlow) > (f.FlowLimit<<20) {
		return fmt.Errorf("%s: flow limit exceeded", label)
	}
	if !f.TimeLimit.IsZero() && f.TimeLimit.Before(now) {
		return fmt.Errorf("%s: time limit exceeded", label)
	}
	return nil
}

func (c *FlowConn) Read(p []byte) (int, error) {
	n, err := c.RWConn.Read(p)
	n64 := int64(n)
	c.taskFlow.Add(0, n64)
	c.clientFlow.Add(n64, n64)
	now := time.Now()
	if err := CheckFlowLimits(c.taskFlow, "Task", now); err != nil {
		return n, err
	}
	if err := CheckFlowLimits(c.clientFlow, "Client", now); err != nil {
		return n, err
	}
	return n, err
}

func (c *FlowConn) Write(p []byte) (int, error) {
	n, err := c.RWConn.Write(p)
	n64 := int64(n)
	c.taskFlow.Add(n64, 0)
	c.clientFlow.Add(n64, n64)
	now := time.Now()
	if err := CheckFlowLimits(c.taskFlow, "Task", now); err != nil {
		return n, err
	}
	if err := CheckFlowLimits(c.clientFlow, "Client", now); err != nil {
		return n, err
	}
	return n, err
}

type TimeoutConn struct {
	net.Conn
	idleTimeout time.Duration
}

func NewTimeoutConn(c net.Conn, idle time.Duration) net.Conn {
	return &TimeoutConn{Conn: c, idleTimeout: idle}
}

func (c *TimeoutConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.idleTimeout))
	return c.Conn.Read(b)
}

func (c *TimeoutConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.idleTimeout))
	return c.Conn.Write(b)
}

func NewTimeoutTLSConn(raw net.Conn, cfg *tls.Config, idle, handshakeTimeout time.Duration) (net.Conn, error) {
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return NewTimeoutConn(tlsConn, idle), nil
}

func GetTlsConn(c net.Conn, sni string) (net.Conn, error) {
	serverName := common.RemovePortFromHost(sni)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
	c = tls.Client(c, tlsConf)
	if err := c.(*tls.Conn).Handshake(); err != nil {
		logs.Error("TLS handshake with backend failed: %v", err)
		return nil, err
	}
	return c, nil
}
