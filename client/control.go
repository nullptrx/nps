package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/config"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/version"
	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/net/proxy"
)

const MaxPad = 64

var Ver = version.GetLatestIndex()
var SkipTLSVerify = false

func init() {
	rand.Seed(time.Now().UnixNano())
}

func GetTaskStatus(path string) {
	cnf, err := config.NewConfig(path)
	if err != nil {
		log.Fatalln(err)
	}
	c, err := NewConn(cnf.CommonConfig.Tp, cnf.CommonConfig.VKey, cnf.CommonConfig.Server, common.WORK_CONFIG, cnf.CommonConfig.ProxyUrl)
	if err != nil {
		log.Fatalln(err)
	}
	if _, err := c.Write([]byte(common.WORK_STATUS)); err != nil {
		log.Fatalln(err)
	}
	//read now vKey and write to server
	if f, err := common.ReadAllFromFile(filepath.Join(common.GetTmpPath(), "npc_vkey.txt")); err != nil {
		log.Fatalln(err)
	} else if _, err := c.Write([]byte(crypt.Blake2b(string(f)))); err != nil {
		log.Fatalln(err)
	}
	var isPub bool
	_ = binary.Read(c, binary.LittleEndian, &isPub)
	if l, err := c.GetLen(); err != nil {
		log.Fatalln(err)
	} else if b, err := c.GetShortContent(l); err != nil {
		log.Fatalln(err)
	} else {
		arr := strings.Split(string(b), common.CONN_DATA_SEQ)
		for _, v := range cnf.Hosts {
			if common.InStrArr(arr, v.Remark) {
				log.Println(v.Remark, "ok")
			} else {
				log.Println(v.Remark, "not running")
			}
		}
		for _, v := range cnf.Tasks {
			ports := common.GetPorts(v.Ports)
			if v.Mode == "secret" {
				ports = append(ports, 0)
			}
			for _, vv := range ports {
				var remark string
				if len(ports) > 1 {
					remark = v.Remark + "_" + strconv.Itoa(vv)
				} else {
					remark = v.Remark
				}
				if common.InStrArr(arr, remark) {
					log.Println(remark, "ok")
				} else {
					log.Println(remark, "not running")
				}
			}
		}
	}
	os.Exit(0)
}

var errAdd = errors.New("the server returned an error, which port or host may have been occupied or not allowed to open")

func StartFromFile(path string) {
	cnf, err := config.NewConfig(path)
	if err != nil || cnf.CommonConfig == nil {
		logs.Error("Config file %s loading error %v", path, err)
		os.Exit(0)
	}
	logs.Info("Loading configuration file %s successfully", path)

	common.SetCustomDNS(cnf.CommonConfig.DnsServer)

	logs.Info("the version of client is %s, the core version of client is %s", version.VERSION, version.GetLatest())

	common.SetNtpServer(cnf.CommonConfig.NtpServer)
	if cnf.CommonConfig.NtpInterval > 0 {
		common.SetNtpInterval(time.Duration(cnf.CommonConfig.NtpInterval) * time.Minute)
	}
	common.SyncTime()

	first := true
	for {
		if !first && !cnf.CommonConfig.AutoReconnection {
			return
		}
		if !first {
			logs.Info("Reconnecting...")
			time.Sleep(time.Second * 5)
		}
		first = false

		if cnf.CommonConfig.TlsEnable {
			cnf.CommonConfig.Tp = "tls"
		}
		c, err := NewConn(cnf.CommonConfig.Tp, cnf.CommonConfig.VKey, cnf.CommonConfig.Server, common.WORK_CONFIG, cnf.CommonConfig.ProxyUrl)
		if err != nil {
			logs.Error("%v", err)
			continue
		}

		var isPub bool
		_ = binary.Read(c, binary.LittleEndian, &isPub)

		// get tmp password
		var b []byte
		vkey := cnf.CommonConfig.VKey
		if isPub {
			// send global configuration to server and get status of config setting
			if _, err := c.SendInfo(cnf.CommonConfig.Client, common.NEW_CONF); err != nil {
				logs.Error("%v", err)
				_ = c.Close()
				continue
			}
			if !c.GetAddStatus() {
				logs.Error("the web_user may have been occupied!")
				_ = c.Close()
				continue
			}

			if b, err = c.GetShortContent(16); err != nil {
				logs.Error("%v", err)
				_ = c.Close()
				continue
			}
			vkey = string(b)
		}

		if err := ioutil.WriteFile(filepath.Join(common.GetTmpPath(), "npc_vkey.txt"), []byte(vkey), 0600); err != nil {
			logs.Debug("Failed to write vkey file: %v", err)
			//c.Close()
			//continue
		}

		//send hosts to server
		for _, v := range cnf.Hosts {
			if _, err := c.SendInfo(v, common.NEW_HOST); err != nil {
				logs.Error("%v", err)
				continue
			}
			if !c.GetAddStatus() {
				logs.Error("%v %s", errAdd, v.Host)
				continue
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		fsm := NewFileServerManager(ctx)
		p2pm := NewP2PManager(ctx)

		//send  task to server
		for _, v := range cnf.Tasks {
			if _, err := c.SendInfo(v, common.NEW_TASK); err != nil {
				logs.Error("%v", err)
				continue
			}
			if !c.GetAddStatus() {
				logs.Error("%v %s %s", errAdd, v.Ports, v.Remark)
				continue
			}
			if v.Mode == "file" {
				//start local file server
				go fsm.StartFileServer(cnf.CommonConfig, v, vkey)
			}
		}

		//create local server secret or p2p
		for _, v := range cnf.LocalServer {
			go p2pm.StartLocalServer(v, cnf.CommonConfig)
		}

		_ = c.Close()
		if cnf.CommonConfig.Client.WebUserName == "" || cnf.CommonConfig.Client.WebPassword == "" {
			logs.Info("web access login username:user password:%s", vkey)
		} else {
			logs.Info("web access login username:%s password:%s", cnf.CommonConfig.Client.WebUserName, cnf.CommonConfig.Client.WebPassword)
		}

		NewRPClient(cnf.CommonConfig.Server, vkey, cnf.CommonConfig.Tp, cnf.CommonConfig.ProxyUrl, cnf, cnf.CommonConfig.DisconnectTime).Start()
		//CloseLocalServer()
		fsm.CloseAll()
		p2pm.Close()
		cancel()
	}
}

func VerifyState(state tls.ConnectionState, host string) (fingerprint []byte, verified bool) {
	if len(state.PeerCertificates) == 0 {
		return nil, false
	}
	leaf := state.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		inter.AddCert(cert)
	}
	roots, _ := x509.SystemCertPool()
	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
	}
	if _, err := leaf.Verify(opts); err != nil {
		verified = false
	} else {
		verified = true
	}
	sum := sha256.Sum256(leaf.Raw)
	return sum[:], verified
}

func VerifyTLS(connection net.Conn, host string) (fingerprint []byte, verified bool) {
	var tlsConn *tls.Conn
	if tc, ok := connection.(*conn.TlsConn); ok {
		tlsConn = tc.Conn
	} else if std, ok := connection.(*tls.Conn); ok {
		tlsConn = std
	} else {
		return nil, false
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, false
	}
	return VerifyState(tlsConn.ConnectionState(), host)
}

func EnsurePort(server string, tp string) string {
	_, port, err := net.SplitHostPort(server)
	if err == nil && port != "" {
		return server
	}
	if p, ok := common.DefaultPort[tp]; ok {
		return net.JoinHostPort(server, p)
	}
	return server
}

// NewConn Create a new connection with the server and verify it
func NewConn(tp string, vkey string, server string, connType string, proxyUrl string) (*conn.Conn, error) {
	//logs.Debug("NewConn: %s %s %s %s %s", tp, vkey, server, connType, proxyUrl)
	var err error
	var connection net.Conn
	var sess *kcp.UDPSession
	var path string
	var isTls = false
	var tlsVerify = false
	var tlsFp []byte

	timeout := time.Second * 10
	dialer := net.Dialer{Timeout: timeout}
	alpn := "nps"
	server, path = common.SplitServerAndPath(server)
	if path == "" {
		path = "/ws"
	} else {
		alpn = strings.TrimSpace(strings.TrimPrefix(path, "/"))
	}
	server = EnsurePort(server, tp)
	host := common.GetIpByAddr(server)
	if common.IsDomain(host) {
		host = ""
	}
	//logs.Debug("Server: %s Path: %s", server, path)
	if HasFailed {
		server, err = common.GetFastAddr(server, tp)
		if err != nil {
			logs.Debug("Server: %s Path: %s Error: %v", server, path, err)
		}
	}

	if tp == "tcp" || tp == "tls" || tp == "ws" || tp == "wss" {
		var rawConn net.Conn
		if proxyUrl != "" {
			u, er := url.Parse(proxyUrl)
			if er != nil {
				return nil, er
			}
			switch u.Scheme {
			case "socks5":
				n, er := proxy.FromURL(u, nil)
				if er != nil {
					return nil, er
				}
				rawConn, err = n.Dial("tcp", server)
			default:
				rawConn, err = NewHttpProxyConn(u, server)
			}
		} else {
			rawConn, err = dialer.Dial("tcp", server)
		}
		if err != nil {
			return nil, err
		}

		switch tp {
		case "tcp":
			connection = rawConn
		case "tls":
			isTls = true
			conf := &tls.Config{InsecureSkipVerify: true}
			connection, err = conn.NewTlsConn(rawConn, timeout, conf)
			if err != nil {
				return nil, err
			}
			tlsFp, tlsVerify = VerifyTLS(connection, host)
		case "ws":
			urlStr := "ws://" + server + path
			wsConn, _, err := conn.DialWS(rawConn, urlStr, timeout)
			if err != nil {
				return nil, err
			}
			connection = conn.NewWsConn(wsConn)
		case "wss":
			isTls = true
			urlStr := "wss://" + server + path
			wsConn, _, err := conn.DialWSS(rawConn, urlStr, timeout)
			if err != nil {
				return nil, err
			}
			if underlying := wsConn.UnderlyingConn(); underlying != nil {
				tlsFp, tlsVerify = VerifyTLS(underlying, host)
			}
			connection = conn.NewWsConn(wsConn)
		}
	} else if tp == "quic" {
		isTls = true
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{alpn},
		}
		quicConfig := &quic.Config{
			KeepAlivePeriod:    10 * time.Second,
			MaxIdleTimeout:     30 * time.Second,
			MaxIncomingStreams: 100000,
		}
		ctx := context.Background()
		sess, err := quic.DialAddr(ctx, server, tlsCfg, quicConfig)
		if err != nil {
			return nil, fmt.Errorf("quic dial error: %w", err)
		}
		state := sess.ConnectionState().TLS
		tlsFp, tlsVerify = VerifyState(state, host)
		stream, err := sess.OpenStreamSync(ctx)
		if err != nil {
			return nil, fmt.Errorf("quic open stream error: %w", err)
		}
		connection = conn.NewQuicConn(stream, sess)
	} else {
		sess, err = kcp.DialWithOptions(server, nil, 10, 3)
		if err == nil {
			conn.SetUdpSession(sess)
			connection = sess
		}
	}

	if err != nil {
		return nil, err
	}

	if connection == nil {
		return nil, fmt.Errorf("NewConn: unexpected nil connection for tp=%q server=%q", tp, server)
	}

	//logs.Debug("SetDeadline")
	_ = connection.SetDeadline(time.Now().Add(timeout))
	defer connection.SetDeadline(time.Time{})

	c := conn.NewConn(connection)
	if _, err := c.BufferWrite([]byte(common.CONN_TEST)); err != nil {
		return nil, err
	}
	minVerBytes := []byte(version.GetVersion(Ver))
	if err := c.WriteLenContent(minVerBytes); err != nil {
		return nil, err
	}
	vs := []byte(version.VERSION)
	padLen := rand.Intn(MaxPad)
	if padLen > 0 {
		vs = append(vs, make([]byte, padLen)...)
	}
	if err := c.WriteLenContent(vs); err != nil {
		return nil, err
	}

	if Ver == 0 {
		// 0.26.0
		b, err := c.GetShortContent(32)
		if err != nil {
			logs.Error("%v", err)
			return nil, err
		}
		if crypt.Md5(version.GetVersion(Ver)) != string(b) {
			logs.Warn("The client does not match the server version. The current core version of the client is %s", version.GetVersion(Ver))
			//return nil, err
		}
		if _, err := c.BufferWrite([]byte(crypt.Md5(vkey))); err != nil {
			return nil, err
		}
		if s, err := c.ReadFlag(); err != nil {
			return nil, err
		} else if s == common.VERIFY_EER {
			return nil, errors.New(fmt.Sprintf("Validation key %s incorrect", vkey))
		}
		if _, err := c.Write([]byte(connType)); err != nil {
			return nil, err
		}
	} else {
		// 0.27.0
		ts := common.TimeNow().Unix() - int64(rand.Intn(6))
		if _, err := c.BufferWrite(common.TimestampToBytes(ts)); err != nil {
			return nil, err
		}
		if _, err := c.BufferWrite([]byte(crypt.Blake2b(vkey))); err != nil {
			return nil, err
		}
		var infoBuf []byte
		if Ver < 3 {
			// 0.27.0 0.28.0
			var err error
			infoBuf, err = crypt.EncryptBytes(common.EncodeIP(common.GetOutboundIP()), vkey)
			if err != nil {
				return nil, err
			}
		} else {
			// 0.29.0
			ipPart := common.EncodeIP(common.GetOutboundIP()) // 17bit
			tpBytes := []byte(tp)
			tpLen := len(tpBytes)
			if tpLen > 32 {
				return nil, fmt.Errorf("tp too long: %d bytes (max %d)", tpLen, 32)
			}
			length := byte(tpLen)
			// IP(17 bit) + len(1 bit) + tpBytes
			buf := make([]byte, 0, len(ipPart)+1+len(tpBytes))
			buf = append(buf, ipPart...)
			buf = append(buf, length)
			buf = append(buf, tpBytes...)
			var err error
			infoBuf, err = crypt.EncryptBytes(buf, vkey)
			if err != nil {
				return nil, err
			}
		}
		if err := c.WriteLenContent(infoBuf); err != nil {
			return nil, err
		}
		randBuf, err := common.RandomBytes(1000)
		if err != nil {
			return nil, err
		}
		if err := c.WriteLenContent(randBuf); err != nil {
			return nil, err
		}
		hmacBuf := crypt.ComputeHMAC(vkey, ts, minVerBytes, vs, infoBuf, randBuf)
		if _, err := c.BufferWrite(hmacBuf); err != nil {
			return nil, err
		}
		b, err := c.GetShortContent(32)
		if err != nil {
			logs.Error("error reading server response: %v", err)
			return nil, errors.New(fmt.Sprintf("Validation key %s incorrect", vkey))
		}
		if !bytes.Equal(b, crypt.ComputeHMAC(vkey, ts, hmacBuf, []byte(version.GetVersion(Ver)))) {
			logs.Warn("The client does not match the server version. The current core version of the client is %s", version.GetVersion(Ver))
			return nil, err
		}
		if Ver > 1 {
			fpBuf, err := c.GetShortLenContent()
			if err != nil {
				return nil, err
			}
			fpDec, err := crypt.DecryptBytes(fpBuf, vkey)
			if err != nil {
				return nil, err
			}
			if !SkipTLSVerify && isTls && !tlsVerify && !bytes.Equal(fpDec, tlsFp) {
				logs.Warn("Certificate verification failed. To skip verification, please set -skip_verify=true")
				return nil, errors.New("validation cert incorrect")
			}
			crypt.AddTrustedCert(vkey, fpDec)
			if Ver > 3 {
				_, err := c.GetShortLenContent()
				if err != nil {
					return nil, err
				}
			}
		}
		if _, err := c.BufferWrite([]byte(connType)); err != nil {
			return nil, err
		}
		if Ver > 3 {
			// v0.30.0
			randByte, err := common.RandomBytes(1000)
			if err != nil {
				return nil, err
			}
			if err := c.WriteLenContent(randByte); err != nil {
				return nil, err
			}
		}
		if err := c.FlushBuf(); err != nil {
			return nil, err
		}
	}

	c.SetAlive()

	return c, nil
}

// NewHttpProxyConn http proxy connection
func NewHttpProxyConn(proxyURL *url.URL, remoteAddr string) (net.Conn, error) {
	proxyConn, err := net.DialTimeout("tcp", proxyURL.Host, 10*time.Second)
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: remoteAddr},
		Host:   remoteAddr,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		req.SetBasicAuth(username, password)
	}
	if err := req.Write(proxyConn); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
	if err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = proxyConn.Close()
		return nil, errors.New("proxy CONNECT failed: " + resp.Status)
	}
	return proxyConn, nil
}

// get a basic auth string
func getBasicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
