package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/beego/beego"
	"github.com/djylb/nps/lib/cache"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/pkg/errors"
)

type HttpsServer struct {
	httpServer
	listener        net.Listener
	httpListener    *HttpsListener
	srv             *http.Server
	cert            *cache.CertManager
	hasDefaultCert  bool
	defaultCertHash string
	defaultCertFile string
	defaultKeyFile  string
}

func NewHttpsServer(l net.Listener, bridge NetBridge, task *file.Tunnel) *HttpsServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	https := &HttpsServer{
		listener: l,
		httpServer: httpServer{
			BaseServer: BaseServer{
				task:            task,
				bridge:          bridge,
				allowLocalProxy: allowLocalProxy,
				Mutex:           sync.Mutex{},
			},
		},
		defaultCertFile: beego.AppConfig.String("https_default_cert_file"),
		defaultKeyFile:  beego.AppConfig.String("https_default_key_file"),
	}

	_, https.hasDefaultCert = common.LoadCert(https.defaultCertFile, https.defaultKeyFile)
	https.defaultCertHash = crypt.FNV1a64("file", https.defaultCertFile, https.defaultKeyFile)

	maxNum := beego.AppConfig.DefaultInt("ssl_cache_max", 0)
	reload := beego.AppConfig.DefaultInt("ssl_cache_reload", 0)
	idle := beego.AppConfig.DefaultInt("ssl_cache_idle", 60)
	https.cert = cache.NewCertManager(maxNum, time.Duration(reload)*time.Second, time.Duration(idle)*time.Minute)
	https.httpListener = NewHttpsListener(l)
	https.srv = https.NewServer(0, "https")

	go func() {
		if err := https.srv.Serve(https.httpListener); err != nil && err != http.ErrServerClosed {
			logs.Error("HTTPS server exit: %v", err)
		}
	}()

	return https
}

func (https *HttpsServer) Start() error {
	conn.Accept(https.listener, func(c net.Conn) {
		helloInfo, rb, err := crypt.ReadClientHello(c, nil)
		if err != nil || helloInfo == nil {
			logs.Warn("Failed to read clientHello from %v, err=%v", c.RemoteAddr(), err)
			// Check if the request is an HTTP request.
			checkHTTPAndRedirect(c, rb)
			return
		}

		serverName := helloInfo.ServerName
		if serverName == "" {
			logs.Debug("IP access to HTTPS port is not allowed. Remote address: %v", c.RemoteAddr())
			c.Close()
			return
		}

		host, err := file.GetDb().FindCertByHost(serverName)
		if err != nil {
			c.Close()
			logs.Debug("The URL %s cannot be parsed! Remote address: %v", serverName, c.RemoteAddr())
			return
		}

		if host.HttpsJustProxy {
			logs.Debug("Certificate handled by backend")
			https.handleHttpsProxy(host, c, rb, serverName)
			return
		}

		cert, err := https.cert.Get(host.CertFile, host.KeyFile, host.CertType, host.CertHash)
		if err != nil {
			if https.hasDefaultCert {
				cert, err = https.cert.Get(https.defaultCertFile, https.defaultKeyFile, "file", https.defaultCertHash)
				if err != nil {
					logs.Error("Failed to load certificate: %v", err)
				}
			}
			if err != nil {
				logs.Debug("Certificate handled by backend")
				https.handleHttpsProxy(host, c, rb, serverName)
				return
			}
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
		acceptConn := conn.NewConn(c)
		acceptConn.Rb = rb
		tlsConn := tls.Server(acceptConn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return
		}

		https.httpListener.acceptConn <- conn.NewConn(tlsConn)
	})
	return nil
}

func checkHTTPAndRedirect(c net.Conn, rb []byte) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.Close()

	logs.Debug("Pre-read rb content: %q", string(rb))

	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(rb), c))
	req, err := http.ReadRequest(reader)
	if err != nil {
		logs.Warn("Failed to parse HTTP request from %v, err=%v", c.RemoteAddr(), err)
		return
	}
	logs.Debug("HTTP Request Sent to HTTPS Port")
	req.URL.Scheme = "https"
	c.SetDeadline(time.Time{})

	_, err = file.GetDb().GetInfoByHost(req.Host, req)
	if err != nil {
		logs.Debug("Host not found: %s %s %s", req.URL.Scheme, req.Host, req.RequestURI)
		return
	}

	redirectURL := "https://" + req.Host + req.RequestURI

	response := "HTTP/1.1 302 Found\r\n" +
		"Location: " + redirectURL + "\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"

	if _, writeErr := c.Write([]byte(response)); writeErr != nil {
		logs.Error("Failed to write redirect response to %v, err=%v", c.RemoteAddr(), writeErr)
	} else {
		logs.Info("Redirected HTTP request from %v to %s", c.RemoteAddr(), redirectURL)
	}
}

func (https *HttpsServer) handleHttpsProxy(host *file.Host, c net.Conn, rb []byte, sni string) {
	if err := https.CheckFlowAndConnNum(host.Client); err != nil {
		logs.Debug("Client id %d, host id %d, error %v during https connection", host.Client.Id, host.Id, err)
		c.Close()
		return
	}
	defer host.Client.CutConn()

	targetAddr, err := host.Target.GetRandomTarget()
	if err != nil {
		logs.Warn("%v", err)
		c.Close()
		return
	}
	logs.Info("New HTTPS connection, clientId %d, host %s, remote address %v", host.Client.Id, sni, c.RemoteAddr())
	https.DealClient(conn.NewConn(c), host.Client, targetAddr, rb, common.CONN_TCP, nil, []*file.Flow{host.Flow, host.Client.Flow}, host.Target.ProxyProtocol, host.Target.LocalProxy, nil)
}

func (https *HttpsServer) Close() error {
	https.srv.Close()
	close(https.httpListener.acceptConn)
	https.cert.Stop()
	return https.listener.Close()
}

// HttpsListener wraps a parent listener.
type HttpsListener struct {
	acceptConn     chan *conn.Conn
	parentListener net.Listener
}

func NewHttpsListener(l net.Listener) *HttpsListener {
	return &HttpsListener{
		parentListener: l,
		acceptConn:     make(chan *conn.Conn, 1024),
	}
}

func (httpsListener *HttpsListener) Accept() (net.Conn, error) {
	httpsConn, ok := <-httpsListener.acceptConn
	if !ok {
		return nil, errors.New("failed to get connection")
	}
	return httpsConn, nil
}

func (httpsListener *HttpsListener) Close() error {
	return nil
}

func (httpsListener *HttpsListener) Addr() net.Addr {
	return httpsListener.parentListener.Addr()
}
