package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/djylb/nps/lib/logs"
)

var (
	cert       tls.Certificate
	trustedSet = make(map[string]struct{})
	vkeyToFp   = make(map[string]string)
	SkipVerify = false
)

func InitTls(customCert tls.Certificate) {
	if len(customCert.Certificate) > 0 {
		cert = customCert
		logs.Info("Custom certificate loaded successfully.")
		return
	}
	commonName := gofakeit.DomainName()
	organization := gofakeit.Company()
	c, k, err := generateKeyPair(commonName, organization)
	if err != nil {
	}
	if err == nil {
		cert, err = tls.X509KeyPair(c, k)
	}
	if err != nil {
		logs.Error("Error initializing crypto certs %v", err)
	}
}

func GetCert() tls.Certificate {
	return cert
}

func GetCertFingerprint() []byte {
	c := GetCert()
	if len(c.Certificate) == 0 {
		return nil
	}
	sum := sha256.Sum256(c.Certificate[0])
	return sum[:]
}

func AddTrustedCert(vkey string, fp []byte) {
	hexFp := hex.EncodeToString(fp)
	if old, ok := vkeyToFp[vkey]; ok {
		delete(trustedSet, old)
	}
	vkeyToFp[vkey] = hexFp
	trustedSet[hexFp] = struct{}{}
}

func NewTlsServerConn(conn net.Conn) net.Conn {
	var err error
	if err != nil {
		logs.Error("%v", err)
		os.Exit(0)
		return nil
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	return tls.Server(conn, config)
}

func NewTlsClientConn(conn net.Conn) net.Conn {
	if SkipVerify {
		return tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	}
	conf := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no server certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			key := hex.EncodeToString(sum[:])
			if _, ok := trustedSet[key]; ok {
				return nil
			}
			return errors.New("untrusted server certificate")
		},
	}
	return tls.Client(conn, conf)
}

func generateKeyPair(commonName, organization string) (rawCert, rawKey []byte, err error) {
	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 10 // ten years
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   commonName,
			Country:      []string{"US"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return
}
