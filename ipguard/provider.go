package ipguard

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type mmdbASNRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}
type mmdbCountryRecord struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type MMDBProvider struct {
	asnPath     string
	countryPath string
	asnDB       atomic.Pointer[maxminddb.Reader]
	countryDB   atomic.Pointer[maxminddb.Reader]
	stopCh      chan struct{}
}

func NewMMDBProvider(asnPath, countryPath string, reloadEvery time.Duration) (*MMDBProvider, error) {
	p := &MMDBProvider{
		asnPath: asnPath, countryPath: countryPath, stopCh: make(chan struct{}),
	}
	load := func() error {
		asn, err := maxminddb.Open(asnPath)
		if err != nil {
			return err
		}
		ctr, err := maxminddb.Open(countryPath)
		if err != nil {
			asn.Close()
			return err
		}
		if old := p.asnDB.Swap(asn); old != nil {
			old.Close()
		}
		if old := p.countryDB.Swap(ctr); old != nil {
			old.Close()
		}
		return nil
	}
	if err := load(); err != nil {
		return nil, err
	}

	if reloadEvery > 0 {
		go func() {
			t := time.NewTicker(reloadEvery)
			defer t.Stop()
			var lastASN, lastCTR time.Time
			_ = lastASN
			_ = lastCTR
			for {
				select {
				case <-p.stopCh:
					return
				case <-t.C:
					// 简单按 mtime 变化重载
					if newer(p.asnPath, &lastASN) || newer(p.countryPath, &lastCTR) {
						_ = load()
					}
				}
			}
		}()
	}
	return p, nil
}
func newer(path string, last *time.Time) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	mt := fi.ModTime()
	if mt.After(*last) {
		*last = mt
		return true
	}
	return false
}

func (p *MMDBProvider) Lookup(_ context.Context, ip string) (Meta, error) {
	var m Meta
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return m, nil
	}
	var rA mmdbASNRecord
	if err := p.asnDB.Load().Lookup(parsed, &rA); err == nil {
		m.ASN = rA.AutonomousSystemNumber
		m.Org = rA.AutonomousSystemOrganization
	}
	var rC mmdbCountryRecord
	if err := p.countryDB.Load().Lookup(parsed, &rC); err == nil {
		m.Country = rC.Country.IsoCode
	}
	return m, nil
}
func (p *MMDBProvider) Close() error {
	close(p.stopCh)
	if db := p.asnDB.Swap(nil); db != nil {
		db.Close()
	}
	if db := p.countryDB.Swap(nil); db != nil {
		db.Close()
	}
	return nil
}

var DefaultProvider *MMDBProvider

func init() {
	p, err := NewMMDBProvider(
		"/etc/nps/geolite/GeoLite2-ASN.mmdb",
		"/etc/nps/geolite/GeoLite2-Country.mmdb",
		time.Hour, // 文件变更检查周期
	)
	if err != nil {
		panic("ipguard: DefaultProvider init failed: " + err.Error())
	}
	DefaultProvider = p
}
