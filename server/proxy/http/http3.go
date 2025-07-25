package http

import (
	"crypto/tls"
	"net"

	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/quic-go/quic-go/http3"
)

type Http3Server struct {
	*HttpsServer
	udpConn     net.PacketConn
	http3Server *http3.Server
}

func NewHttp3Server(httpsSrv *HttpsServer, udpConn net.PacketConn) *Http3Server {
	return &Http3Server{
		HttpsServer: httpsSrv,
		udpConn:     udpConn,
	}
}

func (h3 *Http3Server) Start() error {
	if h3.http3Port <= 0 {
		return nil
	}

	tlsConfig := &tls.Config{
		NextProtos: []string{"h3"},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			host, err := file.GetDb().FindCertByHost(info.ServerName)
			if err != nil || host.HttpsJustProxy || host.IsClose {
				return nil, nil
			}

			if host.AutoSSL && (h3.httpPort == 80 || h3.httpsPort == 443) {
				return h3.certMagicTls, nil
			}

			cert, err := h3.cert.Get(host.CertFile, host.KeyFile, host.CertType, host.CertHash)
			if err != nil {
				if h3.hasDefaultCert {
					cert, err = h3.cert.Get(h3.defaultCertFile, h3.defaultKeyFile, "file", h3.defaultCertHash)
					if err != nil {
						logs.Error("Failed to load certificate: %v", err)
					}
				}
				if err != nil {
					return nil, nil
				}
			}
			config := &tls.Config{
				Certificates: []tls.Certificate{*cert},
			}
			config.NextProtos = h3.tlsNextProtos
			config.SetSessionTicketKeys(h3.ticketKeys)

			return config, nil
		},
	}
	tlsConfig.SetSessionTicketKeys(h3.ticketKeys)

	h3.http3Server = &http3.Server{
		Handler:   h3.srv.Handler,
		TLSConfig: tlsConfig,
	}

	go func() {
		if err := h3.http3Server.Serve(h3.udpConn); err != nil {
			logs.Error("HTTP/3 Serve error: %v", err)
		}
	}()
	return nil
}

func (h3 *Http3Server) Close() error {
	h3.udpConn.Close()
	h3.http3Server.Close()
	return nil
}
