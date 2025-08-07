package proxy

import (
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

//var httpNum = 0

//go:linkname initBeforeHTTPRun github.com/beego/beego.initBeforeHTTPRun
func initBeforeHTTPRun()

type TunnelModeServer struct {
	BaseServer
	process           process
	listener          net.Listener
	activeConnections sync.Map
}

// NewTunnelModeServer tcp|host|mixproxy
func NewTunnelModeServer(process process, bridge NetBridge, task *file.Tunnel) *TunnelModeServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	s := new(TunnelModeServer)
	s.Bridge = bridge
	s.process = process
	s.Task = task
	s.AllowLocalProxy = allowLocalProxy
	s.activeConnections = sync.Map{} // 初始化连接池
	return s
}

func (s *TunnelModeServer) Start() error {
	if s.Task.ServerIp == "" {
		s.Task.ServerIp = "0.0.0.0"
	}
	return conn.NewTcpListenerAndProcess(common.BuildAddress(s.Task.ServerIp, strconv.Itoa(s.Task.Port)), func(c net.Conn) {
		s.activeConnections.Store(c, struct{}{})
		defer func() {
			s.activeConnections.Delete(c)
			if c != nil {
				_ = c.Close()
			}
		}()

		if s.Bridge.IsServer() {
			if err := s.CheckFlowAndConnNum(s.Task.Client); err != nil {
				logs.Warn("client Id %d, task Id %d, error %v, when tcp connection", s.Task.Client.Id, s.Task.Id, err)
				_ = c.Close()
				return
			}
			defer s.Task.Client.CutConn()
			s.Task.AddConn()
			defer s.Task.CutConn()
		}
		logs.Trace("new tcp connection,local port %d,client %d,remote address %v", s.Task.Port, s.Task.Client.Id, c.RemoteAddr())

		_ = s.process(conn.NewConn(c), s)
	}, &s.listener)
}

func (s *TunnelModeServer) Close() error {
	s.activeConnections.Range(func(key, value interface{}) bool {
		if c, ok := key.(net.Conn); ok {
			_ = c.Close()
			s.activeConnections.Delete(key)
		}
		return true
	})
	s.activeConnections = sync.Map{}
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

func NewWebServer(bridge *bridge.Bridge) *WebServer {
	s := new(WebServer)
	s.Bridge = bridge
	return s
}

type process func(c *conn.Conn, s *TunnelModeServer) error

// ProcessTunnel tcp proxy
func ProcessTunnel(c *conn.Conn, s *TunnelModeServer) error {
	targetAddr, err := s.Task.Target.GetRandomTarget()
	if err != nil {
		if s.Task.Mode != "file" && s.Bridge.IsServer() {
			_ = c.Close()
			logs.Warn("tcp port %d, client Id %d, task Id %d connect error %v", s.Task.Port, s.Task.Client.Id, s.Task.Id, err)
			return err
		}
		targetAddr = ""
	}

	return s.DealClient(c, s.Task.Client, targetAddr, nil, common.CONN_TCP, nil, []*file.Flow{s.Task.Flow, s.Task.Client.Flow}, s.Task.Target.ProxyProtocol, s.Task.Target.LocalProxy, s.Task)
}

// ProcessHttp http proxy
func ProcessHttp(c *conn.Conn, s *TunnelModeServer) error {
	_, addr, rb, err, r := c.GetHost()
	if err != nil {
		_ = c.Close()
		logs.Info("%v", err)
		return err
	}
	if err := s.Auth(r, nil, s.Task.Client.Cnf.U, s.Task.Client.Cnf.P, s.Task.MultiAccount, s.Task.UserAuth); err != nil {
		_, _ = c.Write([]byte(common.ProxyAuthRequiredBytes))
		_ = c.Close()
		return err
	}
	remoteAddr := c.Conn.RemoteAddr().String()
	logs.Debug("http proxy request, client=%d method=%s, host=%s, url=%s, remote address=%s, target=%s", s.Task.Client.Id, r.Method, r.Host, r.URL.RequestURI(), remoteAddr, addr)
	if r.Method == http.MethodConnect {
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		return s.DealClient(c, s.Task.Client, addr, nil, common.CONN_TCP, nil, []*file.Flow{s.Task.Flow, s.Task.Client.Flow}, s.Task.Target.ProxyProtocol, s.Task.Target.LocalProxy, s.Task)
	}
	var server *http.Server

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			//req.RequestURI = ""
			//req.Header.Del("Proxy-Connection")
			//req.Header.Del("Proxy-Authenticate")
			//req.Header.Del("Proxy-Authorization")
			//req.Header.Del("TE")
			//req.Header.Del("Trailers")
			//req.Header.Del("Transfer-Encoding")
			//req.Header.Del("Upgrade")
			//connections := req.Header.Get("Connection")
			//req.Header.Del("Connection")
			//if connections != "" {
			//	for _, h := range strings.Split(connections, ",") {
			//		req.Header.Del(strings.TrimSpace(h))
			//	}
			//}
			req.Header["X-Forwarded-For"] = nil
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 60 * time.Second,
			//DisableKeepAlives:     true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				isLocal := s.AllowLocalProxy && s.Task.Target.LocalProxy || s.Task.Client.Id < 0
				link := conn.NewLink("tcp", addr, s.Task.Client.Cnf.Crypt, s.Task.Client.Cnf.Compress, remoteAddr, isLocal)
				target, err := s.Bridge.SendLinkInfo(s.Task.Client.Id, link, nil)
				if err != nil {
					logs.Trace("DialContext: connection to host %s (target %s) failed: %v", r.Host, addr, err)
					return nil, err
				}
				rawConn := conn.GetConn(target, link.Crypt, link.Compress, s.Task.Client.Rate, true, isLocal)
				return conn.NewFlowConn(rawConn, s.Task.Flow, s.Task.Client.Flow), nil
			},
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			if err == io.EOF {
				//logs.Info("ErrorHandler: io.EOF encountered, writing 521")
				rw.WriteHeader(521)
				//go server.Close()
				return
			}
			logs.Debug("ErrorHandler: proxy error: method=%s, URL=%s, error=%v", req.Method, req.URL.String(), err)
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
			//go server.Close()
		},
	}
	var listener *conn.OneConnListener
	if c.Rb == nil {
		c.Rb = rb
		listener = conn.NewOneConnListener(c)
	} else {
		cc := conn.NewConnWithRb(c, rb)
		listener = conn.NewOneConnListener(cc)
	}
	var shutdownTimerMu sync.Mutex
	var shutdownTimer *time.Timer
	defer func() {
		_ = listener.Close()
		shutdownTimerMu.Lock()
		if shutdownTimer != nil {
			shutdownTimer.Stop()
		}
		shutdownTimerMu.Unlock()
	}()
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		shutdownTimerMu.Lock()
		if shutdownTimer != nil {
			shutdownTimer.Stop()
		}
		shutdownTimerMu.Unlock()
		defer func() {
			//logs.Error("HTTP Proxy Number: %d, Reset timeout", httpNum)
			shutdownTimerMu.Lock()
			shutdownTimer = time.AfterFunc(30*time.Second, func() {
				_ = server.Close()
			})
			shutdownTimerMu.Unlock()
		}()
		proxy.ServeHTTP(w, req)
	})
	server = &http.Server{
		Handler: handler,
	}
	//httpNum++
	//logs.Error("HTTP Proxy Number: %d", httpNum)
	//defer func() {
	//	httpNum--
	//	logs.Error("HTTP Proxy Number: %d", httpNum)
	//}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	//logs.Error("HTTP Proxy Close")
	return nil
}
