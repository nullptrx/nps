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
var bridgePort string
var bridgeTlsPort string
var bridgeWsPort string
var bridgeWssPort string
var bridgePath string
var httpsPort string
var httpPort string
var webPort string

func InitConnectionService() {
	bridgePort = beego.AppConfig.String("bridge_port")
	bridgeTlsPort = beego.AppConfig.String("bridge_tls_port")
	if bridgeTlsPort == "" {
		bridgeTlsPort = beego.AppConfig.String("tls_bridge_port")
	}
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
	logs.Info("server start, the bridge type is tcp, the bridge port is %s", bridgePort)
	var p int
	var err error
	if p, err = strconv.Atoi(bridgePort); err != nil {
		return nil, err
	}
	if pMux != nil {
		return pMux.GetClientListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(beego.AppConfig.String("bridge_ip")), p, ""})
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
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(beego.AppConfig.String("bridge_ip")), p, ""})
}

func GetBridgeWsListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is ws, the bridge port is %s", bridgeWsPort)
	var p int
	var err error
	if p, err = strconv.Atoi(bridgeWsPort); err != nil {
		return nil, err
	}
	if pMux != nil && bridgeWsPort == bridgePort {
		return pMux.GetClientWsListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(beego.AppConfig.String("bridge_ip")), p, ""})
}

func GetBridgeWssListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is wss, the bridge port is %s", bridgeWssPort)
	var p int
	var err error
	if p, err = strconv.Atoi(bridgeWssPort); err != nil {
		return nil, err
	}
	if pMux != nil && bridgeWssPort == bridgePort {
		return pMux.GetClientWssListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(beego.AppConfig.String("bridge_ip")), p, ""})
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
