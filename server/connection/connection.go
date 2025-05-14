package connection

import (
	"net"
	"os"
	"strconv"

	"github.com/beego/beego"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/pmux"
)

var pMux *pmux.PortMux
var bridgeIp string
var bridgeTcpIp string
var bridgeTlsIp string
var bridgeWsIp string
var bridgeWssIp string
var bridgePort string
var bridgeTcpPort string
var bridgeTlsPort string
var bridgeWsPort string
var bridgeWssPort string
var bridgePath string
var httpsPort string
var httpPort string
var webPort string

func InitConnectionService() {
	bridgeIp = beego.AppConfig.String("bridge_ip")
	bridgeTcpIp = beego.AppConfig.DefaultString("bridge_tcp_ip", bridgeIp)
	bridgeTlsIp = beego.AppConfig.DefaultString("bridge_tls_ip", bridgeIp)
	bridgeWsIp = beego.AppConfig.DefaultString("bridge_ws_ip", bridgeIp)
	bridgeWssIp = beego.AppConfig.DefaultString("bridge_wss_ip", bridgeIp)
	bridgePort = beego.AppConfig.String("bridge_port")
	bridgeTcpPort = beego.AppConfig.DefaultString("bridge_tcp_port", bridgePort)
	bridgeTlsPort = beego.AppConfig.DefaultString("bridge_tls_port", beego.AppConfig.String("tls_bridge_port"))
	bridgeWsPort = beego.AppConfig.String("bridge_ws_port")
	bridgeWssPort = beego.AppConfig.String("bridge_wss_port")
	bridgePath = beego.AppConfig.String("bridge_path")
	httpsPort = beego.AppConfig.String("https_proxy_port")
	httpPort = beego.AppConfig.String("http_proxy_port")
	webPort = beego.AppConfig.String("web_port")

	if httpPort == bridgePort || httpsPort == bridgePort || webPort == bridgePort || bridgeTlsPort == bridgePort {
		port, err := strconv.Atoi(bridgePort)
		if err != nil {
			logs.Error("%v", err)
			os.Exit(0)
		}
		pMux = pmux.NewPortMux(port, beego.AppConfig.String("web_host"), beego.AppConfig.String("bridge_host"))
	}
}

func GetBridgeTcpListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is tcp, the bridge port is %s", bridgeTcpPort)
	var p int
	var err error
	if p, err = strconv.Atoi(bridgeTcpPort); err != nil {
		return nil, err
	}
	if pMux != nil && bridgeTcpPort == bridgePort {
		return pMux.GetClientListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(bridgeTcpIp), p, ""})
}

func GetBridgeTlsListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is tls, the bridge port is %s", bridgeTlsPort)
	var p int
	var err error
	if p, err = strconv.Atoi(bridgeTlsPort); err != nil {
		return nil, err
	}
	if pMux != nil && bridgeTlsPort == bridgePort {
		return pMux.GetClientTlsListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(bridgeTlsIp), p, ""})
}

func GetBridgeWsListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is ws, the bridge port is %s, the bridge path is %s", bridgeWsPort, bridgePath)
	var p int
	var err error
	if p, err = strconv.Atoi(bridgeWsPort); err != nil {
		return nil, err
	}
	if pMux != nil && bridgeWsPort == bridgePort {
		return pMux.GetClientWsListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(bridgeWsIp), p, ""})
}

func GetBridgeWssListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is wss, the bridge port is %s, the bridge path is %s", bridgeWssPort, bridgePath)
	var p int
	var err error
	if p, err = strconv.Atoi(bridgeWssPort); err != nil {
		return nil, err
	}
	if pMux != nil && bridgeWssPort == bridgePort {
		return pMux.GetClientWssListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(bridgeWssIp), p, ""})
}

func GetHttpListener() (net.Listener, error) {
	if pMux != nil && httpPort == bridgePort {
		logs.Info("start http listener, port is %s", bridgePort)
		return pMux.GetHttpListener(), nil
	}
	logs.Info("start http listener, port is %s", httpPort)
	return getTcpListener(beego.AppConfig.String("http_proxy_ip"), httpPort)
}

func GetHttpsListener() (net.Listener, error) {
	if pMux != nil && httpsPort == bridgePort {
		logs.Info("start https listener, port is %s", bridgePort)
		return pMux.GetHttpsListener(), nil
	}
	logs.Info("start https listener, port is %s", httpsPort)
	return getTcpListener(beego.AppConfig.String("http_proxy_ip"), httpsPort)
}

func GetWebManagerListener() (net.Listener, error) {
	if pMux != nil && webPort == bridgePort {
		logs.Info("Web management start, access port is %s", bridgePort)
		return pMux.GetManagerListener(), nil
	}
	logs.Info("web management start, access port is %s", webPort)
	return getTcpListener(beego.AppConfig.String("web_ip"), webPort)
}

func getTcpListener(ip, p string) (net.Listener, error) {
	port, err := strconv.Atoi(p)
	if err != nil {
		logs.Error("%v", err)
		os.Exit(0)
	}
	if ip == "" {
		ip = "0.0.0.0"
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(ip), port, ""})
}
