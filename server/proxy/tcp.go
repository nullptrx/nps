package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/beego/beego"
	"github.com/djylb/nps/bridge"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/server/connection"
)

var _ = unsafe.Sizeof(0)

//go:linkname initBeforeHTTPRun github.com/beego/beego.initBeforeHTTPRun
func initBeforeHTTPRun()

type TunnelModeServer struct {
	BaseServer
	process           process
	listener          net.Listener
	activeConnections sync.Map
}

// tcp|http|host
func NewTunnelModeServer(process process, bridge NetBridge, task *file.Tunnel) *TunnelModeServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	s := new(TunnelModeServer)
	s.bridge = bridge
	s.process = process
	s.task = task
	s.allowLocalProxy = allowLocalProxy
	s.activeConnections = sync.Map{} // 初始化连接池
	return s
}

func (s *TunnelModeServer) Start() error {
	return conn.NewTcpListenerAndProcess(common.BuildAddress(s.task.ServerIp, strconv.Itoa(s.task.Port)), func(c net.Conn) {
		s.activeConnections.Store(c, struct{}{})
		defer func() {
			s.activeConnections.Delete(c)
			if c != nil {
				c.Close()
			}
		}()

		if err := s.CheckFlowAndConnNum(s.task.Client); err != nil {
			logs.Warn("client id %d, task id %d, error %v, when tcp connection", s.task.Client.Id, s.task.Id, err)
			c.Close()
			return
		}

		logs.Trace("new tcp connection,local port %d,client %d,remote address %v", s.task.Port, s.task.Client.Id, c.RemoteAddr())

		s.process(conn.NewConn(c), s)
		s.task.Client.CutConn()
	}, &s.listener)
}

func (s *TunnelModeServer) Close() error {
	s.activeConnections.Range(func(key, value interface{}) bool {
		if c, ok := key.(net.Conn); ok {
			c.Close()
		}
		return true
	})
	return s.listener.Close()
}

type WebServer struct {
	BaseServer
}

func (s *WebServer) Start() error {
	p, _ := beego.AppConfig.Int("web_port")
	if p == 0 {
		stop := make(chan struct{})
		<-stop
	}
	beego.BConfig.WebConfig.Session.SessionOn = true
	beego.SetStaticPath(beego.AppConfig.String("web_base_url")+"/static", filepath.Join(common.GetRunPath(), "web", "static"))
	beego.SetViewsPath(filepath.Join(common.GetRunPath(), "web", "views"))
	err := errors.New("Web management startup failure ")
	var l net.Listener
	if l, err = connection.GetWebManagerListener(); err == nil {
		initBeforeHTTPRun()
		if beego.AppConfig.String("web_open_ssl") == "true" {
			keyPath := beego.AppConfig.String("web_key_file")
			certPath := beego.AppConfig.String("web_cert_file")
			err = http.ServeTLS(l, beego.BeeApp.Handlers, certPath, keyPath)
		} else {
			err = http.Serve(l, beego.BeeApp.Handlers)
		}
	} else {
		logs.Error("%v", err)
	}
	return err
}

func (s *WebServer) Close() error {
	return nil
}

// new
func NewWebServer(bridge *bridge.Bridge) *WebServer {
	s := new(WebServer)
	s.bridge = bridge
	return s
}

type process func(c *conn.Conn, s *TunnelModeServer) error

// tcp proxy
func ProcessTunnel(c *conn.Conn, s *TunnelModeServer) error {
	targetAddr, err := s.task.Target.GetRandomTarget()
	if err != nil {
		if s.task.Mode != "file" {
			c.Close()
			logs.Warn("tcp port %d, client id %d, task id %d connect error %v", s.task.Port, s.task.Client.Id, s.task.Id, err)
			return err
		}
		targetAddr = ""
	}

	return s.DealClient(c, s.task.Client, targetAddr, nil, common.CONN_TCP, nil, []*file.Flow{s.task.Flow, s.task.Client.Flow}, s.task.Target.ProxyProtocol, s.task.Target.LocalProxy, s.task)
}

// http proxy
func ProcessHttp(c *conn.Conn, s *TunnelModeServer) error {
	_, addr, rb, err, r := c.GetHost()
	if err != nil {
		c.Close()
		logs.Info("%v", err)
		return err
	}
	if err := s.auth(r, nil, s.task.Client.Cnf.U, s.task.Client.Cnf.P, s.task.MultiAccount, s.task.UserAuth); err != nil {
		c.Write([]byte(common.ProxyAuthRequiredBytes))
		c.Close()
		return err
	}
	remoteAddr := c.Conn.RemoteAddr().String()
	logs.Info("http proxy request, client=%d method=%s, host=%s, url=%s, remote address=%s, target=%s", s.task.Client.Id, r.Method, r.Host, r.URL.RequestURI(), remoteAddr, addr)
	if r.Method == http.MethodConnect {
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		return s.DealClient(c, s.task.Client, addr, nil, common.CONN_TCP, nil, []*file.Flow{s.task.Flow, s.task.Client.Flow}, s.task.Target.ProxyProtocol, s.task.Target.LocalProxy, s.task)
	}
	//if r.Header.Get("Upgrade") != "" || r.Header.Get(":protocol") != "" {
	if strings.EqualFold(r.Header.Get("Connection"), "Upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		r.RequestURI = ""
		r.Header.Del("Proxy-Connection")
		r.Header.Del("Proxy-Authenticate")
		r.Header.Del("Proxy-Authorization")
		hdr, _ := httputil.DumpRequest(r, false)
		if idx := bytes.Index(rb, []byte("\r\n\r\n")); idx >= 0 {
			rb = append(hdr, rb[idx+4:]...)
		} else {
			rb = hdr
		}
		return s.DealClient(c, s.task.Client, addr, rb, common.CONN_TCP, nil, []*file.Flow{s.task.Flow, s.task.Client.Flow}, s.task.Target.ProxyProtocol, s.task.Target.LocalProxy, s.task)
	}
	var server *http.Server
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.RequestURI = ""
			req.Header.Del("Proxy-Connection")
			req.Header.Del("Proxy-Authenticate")
			req.Header.Del("Proxy-Authorization")
			req.Header.Del("TE")
			req.Header.Del("Trailers")
			req.Header.Del("Transfer-Encoding")
			req.Header.Del("Upgrade")
			connections := req.Header.Get("Connection")
			req.Header.Del("Connection")
			if connections != "" {
				for _, h := range strings.Split(connections, ",") {
					req.Header.Del(strings.TrimSpace(h))
				}
			}
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 60 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				link := conn.NewLink("tcp", addr, s.task.Client.Cnf.Crypt, s.task.Client.Cnf.Compress, remoteAddr, s.task.Target.LocalProxy)
				target, err := s.bridge.SendLinkInfo(s.task.Client.Id, link, nil)
				if err != nil {
					logs.Info("DialContext: connection to host %s (target %s) failed: %v", r.Host, addr, err)
					return nil, err
				}
				rawConn := conn.GetConn(target, link.Crypt, link.Compress, s.task.Client.Rate, true)
				return conn.NewFlowConn(rawConn, s.task.Flow, s.task.Client.Flow), nil
			},
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			if err == io.EOF {
				//logs.Info("ErrorHandler: io.EOF encountered, writing 521")
				rw.WriteHeader(521)
				return
			}
			logs.Warn("ErrorHandler: proxy error: method=%s, URL=%s, error=%v", req.Method, req.URL.String(), err)
			errMsg := err.Error()
			idx := strings.Index(errMsg, "Task")
			if idx == -1 {
				idx = strings.Index(errMsg, "Client")
			}
			if idx != -1 {
				http.Error(rw, errMsg[idx:], http.StatusTooManyRequests)
			} else {
				rw.WriteHeader(http.StatusBadGateway)
			}
		},
	}
	c.Rb = rb
	listener := conn.NewOneConnListener(c)
	defer listener.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		proxy.ServeHTTP(w, req)
		go server.Close()
	})
	server = &http.Server{Handler: handler}
	server.Serve(listener)
	logs.Error("HTTP Proxy Close")
	return nil
}
