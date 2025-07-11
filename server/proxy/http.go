package proxy

import (
	"bufio"
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego"
	"github.com/caddyserver/certmagic"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/goroutine"
	"github.com/djylb/nps/lib/index"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/server/connection"
)

type ctxKey string

const (
	ctxRemoteAddr ctxKey = "nps_remote_addr"
	ctxHost       ctxKey = "nps_host"
	ctxSNI        ctxKey = "nps_sni"
)

type HttpServer struct {
	BaseServer
	httpPort        int
	httpsPort       int
	http3Port       int
	httpServer      *http.Server
	httpsServer     *http.Server
	httpsListener   net.Listener
	http3PacketConn net.PacketConn
	httpProxyCache  *index.AnyIntIndex
	httpOnlyPass    string
	addOrigin       bool
	httpPortStr     string
	httpsPortStr    string
	http3PortStr    string
	magic           *certmagic.Config
	acme            *certmagic.ACMEIssuer
}

func NewHttp(bridge NetBridge, task *file.Tunnel, httpPort, httpsPort, http3Port int, httpOnlyPass string, addOrigin bool, httpProxyCache *index.AnyIntIndex) *HttpServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	return &HttpServer{
		BaseServer: BaseServer{
			task:            task,
			bridge:          bridge,
			allowLocalProxy: allowLocalProxy,
			Mutex:           sync.Mutex{},
		},
		httpPort:       httpPort,
		httpsPort:      httpsPort,
		http3Port:      http3Port,
		httpProxyCache: httpProxyCache,
		httpOnlyPass:   httpOnlyPass,
		addOrigin:      addOrigin,
		httpPortStr:    strconv.Itoa(httpPort),
		httpsPortStr:   strconv.Itoa(httpsPort),
		http3PortStr:   strconv.Itoa(http3Port),
	}
}

func (s *HttpServer) Start() error {
	var err error
	s.errorContent, err = common.ReadAllFromFile(common.ResolvePath(beego.AppConfig.DefaultString("error_page", "web/static/page/error.html")))
	if err != nil {
		s.errorContent = []byte("nps 404")
	}

	certmagic.Default.Logger = logs.ZapLogger
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = beego.AppConfig.String("ssl_email")
	switch strings.ToLower(beego.AppConfig.DefaultString("ssl_ca", "LetsEncrypt")) {
	case "letsencrypt", "le", "prod", "production":
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	case "zerossl", "zero", "zs":
		certmagic.DefaultACME.CA = certmagic.ZeroSSLProductionCA
	case "googletrust", "google", "goog":
		certmagic.DefaultACME.CA = certmagic.GoogleTrustProductionCA
	default:
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}
	certmagic.Default.Storage = &certmagic.FileStorage{
		Path: common.ResolvePath(beego.AppConfig.DefaultString("ssl_path", "ssl")),
	}
	s.magic = certmagic.NewDefault()
	if certmagic.DefaultACME.CA == certmagic.ZeroSSLProductionCA {
		s.magic.Issuers = []certmagic.Issuer{
			&certmagic.ZeroSSLIssuer{
				APIKey: beego.AppConfig.String("ssl_zerossl_api"),
			},
		}
	}
	s.magic.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			h, err := file.GetDb().FindCertByHost(name)
			if err != nil {
				return fmt.Errorf("unknown host %q", name)
			}
			if !h.AutoSSL {
				return fmt.Errorf("AutoSSL disabled for %q", name)
			}
			return nil
		},
	}
	s.acme = certmagic.NewACMEIssuer(s.magic, certmagic.DefaultACME)

	if s.httpPort > 0 {
		s.httpServer = s.NewServer(s.httpPort, "http")
		go func() {
			l, err := connection.GetHttpListener()
			if err != nil {
				logs.Error("Failed to start HTTP listener: %v", err)
				os.Exit(0)
			}
			logs.Info("HTTP server listening on port %d", s.httpPort)
			if err := s.httpServer.Serve(l); err != nil {
				logs.Error("HTTP server stopped: %v", err)
				os.Exit(0)
			}
		}()
	}

	if s.httpsPort > 0 {
		s.httpsServer = s.NewServer(s.httpsPort, "https")
		s.httpsListener, err = connection.GetHttpsListener()
		if err != nil {
			logs.Error("Failed to start HTTPS listener: %v", err)
			os.Exit(0)
		}
		logs.Info("HTTPS server listening on port %d", s.httpsPort)
		httpsServer := NewHttpsServer(s.httpsListener, s.bridge, s.task, s.httpsServer, s.magic)
		go func() {
			if err := httpsServer.Start(); err != nil {
				logs.Error("HTTPS server stopped: %v", err)
				os.Exit(0)
			}
		}()

		if s.http3Port > 0 {
			s.http3PacketConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(connection.HttpIp), Port: s.http3Port})
			if err != nil {
				logs.Error("Failed to start HTTP/3 listener: %v", err)
				os.Exit(0)
			}
			logs.Info("HTTP/3 server listening on port %d", s.http3Port)
			http3Server := NewHttp3Server(httpsServer, s.http3PacketConn)
			go func() {
				if err := http3Server.Start(); err != nil {
					logs.Error("HTTP/3 server stopped: %v", err)
					os.Exit(0)
				}
			}()
		}
	}
	return nil
}

func (s *HttpServer) Close() error {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	if s.httpsServer != nil {
		s.httpsServer.Close()
	}
	if s.httpsListener != nil {
		s.httpsListener.Close()
	}
	if s.http3PacketConn != nil {
		s.http3PacketConn.Close()
	}
	s.httpProxyCache.Clear()
	return nil
}

func (s *HttpServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Get host
	host, err := file.GetDb().GetInfoByHost(r.Host, r)
	if err != nil || host.IsClose {
		//http.Error(w, "404 Host not found", http.StatusNotFound)
		//w.Header().Set("Content-Type", "text/html; charset=utf-8")
		//w.WriteHeader(http.StatusNotFound)
		//w.Write(s.errorContent)
		logs.Debug("Host not found: %s %s %s", r.URL.Scheme, r.Host, r.RequestURI)
		if hj, ok := w.(http.Hijacker); ok {
			c, _, _ := hj.Hijack()
			c.Close()
		}
		return
	}

	// IP Black List
	clientIP := common.GetIpByAddr(r.RemoteAddr)
	if IsGlobalBlackIp(clientIP) || common.IsBlackIp(clientIP, host.Client.VerifyKey, host.Client.BlackIpList) {
		//http.Error(w, "403 Forbidden", http.StatusForbidden)
		logs.Warn("Blocked IP: %s", clientIP)
		if hj, ok := w.(http.Hijacker); ok {
			c, _, _ := hj.Hijack()
			c.Close()
		}
		return
	}

	// AutoSSL
	if host.AutoSSL && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") && (s.httpPort == 80 || s.httpsPort == 443) {
		s.acme.HandleHTTPChallenge(w, r)
		return
	}

	// HTTP-Only
	isHttpOnlyRequest := (s.httpOnlyPass != "" && r.Header.Get("X-NPS-Http-Only") == s.httpOnlyPass)
	if isHttpOnlyRequest {
		r.Header.Del("X-NPS-Http-Only")
	}

	// Auto 301 to HTTPS
	if !isHttpOnlyRequest && host.AutoHttps && r.TLS == nil {
		redirectHost := common.RemovePortFromHost(r.Host)
		if s.httpsPort != 443 {
			redirectHost += ":" + s.httpsPortStr
		}
		http.Redirect(w, r, "https://"+redirectHost+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	// Path Rewrite
	if host.PathRewrite != "" && strings.HasPrefix(r.URL.Path, host.Location) {
		if !host.CompatMode {
			r.Header.Set("X-Original-Path", r.URL.Path)
		}
		r.URL.Path = host.PathRewrite + r.URL.Path[len(host.Location):]
	}

	// Check flow and conn
	if err := s.CheckFlowAndConnNum(host.Client); err != nil {
		http.Error(w, "Access denied: "+err.Error(), http.StatusTooManyRequests)
		logs.Warn("Connection limit exceeded, client id %d, host id %d, error %v", host.Client.Id, host.Id, err)
		return
	}
	defer host.Client.CutConn()
	host.AddConn()
	defer host.CutConn()

	// HTTP Auth
	if r.Header.Get("Upgrade") == "" {
		if err := s.auth(r, nil, host.Client.Cnf.U, host.Client.Cnf.P, host.MultiAccount, host.UserAuth); err != nil {
			logs.Warn("Unauthorized request from %s", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 307 Temporary Redirect
	if host.RedirectURL != "" {
		http.Redirect(w, r, html.UnescapeString(host.RedirectURL), http.StatusTemporaryRedirect)
		return
	}

	logs.Debug("%s request, method %s, host %s, url %s, remote address %s", r.URL.Scheme, r.Method, r.Host, r.URL.Path, r.RemoteAddr)

	sni := r.Host
	if host.HostChange != "" {
		sni = host.HostChange
	}
	ctx := context.WithValue(r.Context(), ctxRemoteAddr, r.RemoteAddr)
	ctx = context.WithValue(ctx, ctxHost, host)
	ctx = context.WithValue(ctx, ctxSNI, sni)
	r = r.WithContext(ctx)

	// WebSocket
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" || r.Header.Get(":protocol") != "" {
		logs.Trace("Handling websocket from %s", r.RemoteAddr)
		s.handleWebsocket(w, r, host, isHttpOnlyRequest)
		return
	}

	var tr *http.Transport
	if v, ok := s.httpProxyCache.Get(host.Id); ok {
		tr = v.(*http.Transport)
	} else {
		tr = &http.Transport{
			ResponseHeaderTimeout: 60 * time.Second,
			DisableKeepAlives:     host.CompatMode,
			DialContext:           s.DialContext,
			DialTLSContext:        s.DialTlsContext,
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
		}
		s.httpProxyCache.Add(host.Id, tr)
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			//req = req.WithContext(context.WithValue(req.Context(), "origReq", r))
			if host.TargetIsHttps {
				req.URL.Scheme = "https"
			} else {
				req.URL.Scheme = "http"
			}
			//logs.Debug("Director: set req.URL.Scheme=%s, req.URL.Host=%s", req.URL.Scheme, req.URL.Host)
			common.ChangeHostAndHeader(req, host.HostChange, host.HeaderChange, isHttpOnlyRequest)
			req.URL.Host = r.Host
			if isHttpOnlyRequest {
				req.Header["X-Forwarded-For"] = nil
			}
		},
		Transport:     tr,
		FlushInterval: 100 * time.Millisecond,
		ModifyResponse: func(resp *http.Response) error {
			// CORS
			if host.AutoCORS {
				origin := resp.Request.Header.Get("Origin")
				if origin != "" && resp.Header.Get("Access-Control-Allow-Origin") == "" {
					logs.Debug("ModifyResponse: setting CORS headers for origin=%s", origin)
					resp.Header.Set("Access-Control-Allow-Origin", origin)
					resp.Header.Set("Access-Control-Allow-Credentials", "true")
				}
			}
			// H3
			if s.http3Port > 0 && r.TLS != nil && !host.HttpsJustProxy && !host.CompatMode {
				resp.Header.Set("Alt-Svc", `h3=":`+s.http3PortStr+`"; ma=86400`)
			}
			common.ChangeResponseHeader(resp, host.RespHeaderChange)
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			s.httpProxyCache.Remove(host.Id)
			if err == io.EOF {
				logs.Info("ErrorHandler: io.EOF encountered, writing 521")
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
				//http.Error(rw, "502 Bad Gateway", http.StatusBadGateway)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadGateway)
				w.Write(s.errorContent)
			}
		},
	}
	rp.ServeHTTP(w, r)
}

func (s *HttpServer) handleWebsocket(w http.ResponseWriter, r *http.Request, host *file.Host, isHttpOnlyRequest bool) {
	// Get target addr
	targetAddr, err := host.Target.GetRandomTarget()
	if err != nil {
		logs.Warn("No backend found for host: %s Err: %v", r.Host, err)
		//http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write(s.errorContent)
		return
	}

	logs.Info("%s websocket request, method %s, host %s, url %s, remote address %s, target %s", r.URL.Scheme, r.Method, r.Host, r.URL.Path, r.RemoteAddr, targetAddr)

	link := conn.NewLink("tcp", targetAddr, host.Client.Cnf.Crypt, host.Client.Cnf.Compress, r.RemoteAddr, host.Target.LocalProxy)
	targetConn, err := s.bridge.SendLinkInfo(host.Client.Id, link, nil)
	if err != nil {
		logs.Info("handleWebsocket: connection to target %s failed: %v", link.Host, err)
		//http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write(s.errorContent)
		return
	}
	rawConn := conn.GetConn(targetConn, link.Crypt, link.Compress, host.Client.Rate, true)
	wsConn := conn.NewRWConn(rawConn)
	var netConn net.Conn = wsConn

	if host.Target.ProxyProtocol != 0 {
		ra, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		if ra == nil || ra.IP == nil {
			ra = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
		}
		la, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
		hdr := conn.BuildProxyProtocolHeaderByAddr(ra, la, host.Target.ProxyProtocol)
		if hdr != nil {
			netConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := netConn.Write(hdr); err != nil {
				netConn.Close()
				return
			}
			netConn.SetWriteDeadline(time.Time{})
		}
	}

	if host.TargetIsHttps {
		sni := r.Context().Value(ctxSNI).(string)
		netConn, err = conn.GetTlsConn(netConn, sni)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			w.Write(s.errorContent)
			return
		}
	}

	common.ChangeHostAndHeader(r, host.HostChange, host.HeaderChange, isHttpOnlyRequest || host.CompatMode)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		logs.Error("handleWebsocket: Hijack not supported")
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		logs.Error("handleWebsocket: Hijack failed")
		return
	}
	//defer clientConn.Close()
	r.Close = false
	if err := r.Write(netConn); err != nil {
		logs.Error("handleWebsocket: failed to write handshake to backend: %v", err)
		netConn.Close()
		clientConn.Close()
		return
	}

	backendReader := bufio.NewReader(netConn)
	resp, err := http.ReadResponse(backendReader, r)
	if err != nil {
		logs.Error("handleWebsocket: failed to read handshake response from backend: %v", err)
		netConn.Close()
		clientConn.Close()
		return
	}

	good := (r.Method == http.MethodConnect && resp.StatusCode == http.StatusOK) ||
		(r.Method != http.MethodConnect && resp.StatusCode == http.StatusSwitchingProtocols)
	if !good {
		logs.Error("handleWebsocket: unexpected status code in handshake: %d", resp.StatusCode)
		netConn.Close()
		clientConn.Close()
		return
	}

	if err := resp.Write(clientBuf); err != nil {
		logs.Error("handleWebsocket: failed to write handshake response to client: %v", err)
		netConn.Close()
		clientConn.Close()
		return
	}
	if err := clientBuf.Flush(); err != nil {
		logs.Error("handleWebsocket: failed to flush handshake response to client: %v", err)
		netConn.Close()
		clientConn.Close()
		return
	}

	if backendReader.Buffered() > 0 {
		pending := make([]byte, backendReader.Buffered())
		if _, err := backendReader.Read(pending); err == nil {
			netConn = conn.NewConnWithRb(netConn, pending)
		} else {
			logs.Error("handleWebsocket: read backend buffered data failed: %v", err)
			netConn.Close()
			clientConn.Close()
			return
		}
	}

	bufReader := clientBuf.Reader
	if bufReader.Buffered() > 0 {
		pending := make([]byte, bufReader.Buffered())
		if _, err := bufReader.Read(pending); err != nil {
			logs.Error("handleWebsocket: failed to read buffered data from client: %v", err)
			netConn.Close()
			clientConn.Close()
			return
		}
		clientConn = conn.NewConnWithRb(clientConn, pending)
	}

	goroutine.Join(clientConn, netConn, []*file.Flow{host.Flow, host.Client.Flow}, s.task, r.RemoteAddr)
}

func (s *HttpServer) NewServer(port int, scheme string) *http.Server {
	return &http.Server{
		Addr: ":" + strconv.Itoa(port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = scheme
			s.handleProxy(w, r)
		}),
		// Disable HTTP/2.
		//TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
}

func (s *HttpServer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	//logs.Debug("DialContext: start dialing; network=%s, addr=%s, using targetAddr=%s", network, addr, targetAddr)
	remote := ctx.Value(ctxRemoteAddr).(string)
	h := ctx.Value(ctxHost).(*file.Host)
	targetAddr, err := h.Target.GetRandomTarget()
	if err != nil {
		logs.Warn("No backend found for h: %s Err: %v", h.Id, err)
		return nil, err
	}
	link := conn.NewLink("tcp", targetAddr, h.Client.Cnf.Crypt, h.Client.Cnf.Compress, remote, s.allowLocalProxy && h.Target.LocalProxy)
	target, err := s.bridge.SendLinkInfo(h.Client.Id, link, nil)
	if err != nil {
		logs.Info("DialContext: connection to h %s (target %s) failed: %v", h.Id, targetAddr, err)
		return nil, err
	}
	rawConn := conn.GetConn(target, link.Crypt, link.Compress, h.Client.Rate, true)
	flowConn := conn.NewFlowConn(rawConn, h.Flow, h.Client.Flow)
	if h.Target.ProxyProtocol != 0 {
		ra, _ := net.ResolveTCPAddr("tcp", remote)
		if ra == nil || ra.IP == nil {
			ra = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
		}
		la, _ := ctx.Value(http.LocalAddrContextKey).(*net.TCPAddr)
		hdr := conn.BuildProxyProtocolHeaderByAddr(ra, la, h.Target.ProxyProtocol)
		if hdr != nil {
			flowConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := flowConn.Write(hdr); err != nil {
				flowConn.Close()
				return nil, fmt.Errorf("write PROXY header: %w", err)
			}
			flowConn.SetWriteDeadline(time.Time{})
		}
	}
	return flowConn, nil
}

func (s *HttpServer) DialTlsContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := s.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	sni := ctx.Value(ctxSNI).(string)
	c, err = conn.GetTlsConn(c, sni)
	if err != nil {
		return nil, err
	}
	return c, nil
}
