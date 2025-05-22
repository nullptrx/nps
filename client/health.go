package client

import (
	"container/heap"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/sheap"
	"github.com/pkg/errors"
)

type HealthChecker struct {
	ctx        context.Context
	cancel     context.CancelFunc
	healths    []*file.Health
	serverConn *conn.Conn
	heap       *sheap.IntHeap
	mu         sync.Mutex
}

func NewHealthChecker(parentCtx context.Context, healths []*file.Health, c *conn.Conn) *HealthChecker {
	ctx, cancel := context.WithCancel(parentCtx)
	hq := &sheap.IntHeap{}
	heap.Init(hq)

	now := time.Now()
	for _, hc := range healths {
		if hc.HealthMaxFail > 0 && hc.HealthCheckInterval > 0 && hc.HealthCheckTimeout > 0 {
			next := now.Add(time.Duration(hc.HealthCheckInterval) * time.Second)
			hc.HealthNextTime = next
			heap.Push(hq, next.Unix())
			hc.HealthMap = make(map[string]int)
		}
	}

	return &HealthChecker{
		ctx:        ctx,
		cancel:     cancel,
		healths:    healths,
		serverConn: c,
		heap:       hq,
	}
}

func (hc *HealthChecker) Start() {
	go hc.loop()
}

func (hc *HealthChecker) Stop() {
	hc.cancel()
}

func (hc *HealthChecker) loop() {
	for {
		if hc.heap.Len() == 0 {
			logs.Error("health check list empty, exiting")
			return
		}
		nextTs := (*hc.heap)[0]
		delay := time.Until(time.Unix(nextTs, 0))
		select {
		case <-hc.ctx.Done():
			return
		case <-time.After(delay):
			hc.runChecks()
		}
	}
}

func (hc *HealthChecker) runChecks() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	now := time.Now()
	for _, h := range hc.healths {
		if !h.HealthNextTime.After(now) {
			hc.doCheck(h)
			h.HealthNextTime = now.Add(time.Duration(h.HealthCheckInterval) * time.Second)
		}
	}
	newHeap := &sheap.IntHeap{}
	heap.Init(newHeap)
	for _, h := range hc.healths {
		heap.Push(newHeap, h.HealthNextTime.Unix())
	}
	hc.heap = newHeap
}

func (hc *HealthChecker) doCheck(h *file.Health) {
	for _, target := range strings.Split(h.HealthCheckTarget, ",") {
		var err error
		timeout := time.Duration(h.HealthCheckTimeout) * time.Second
		if h.HealthCheckType == "tcp" {
			c, errDial := net.DialTimeout("tcp", target, timeout)
			if errDial == nil {
				c.Close()
			} else {
				err = errDial
			}
		} else {
			client := http.Client{Timeout: timeout}
			resp, errGet := client.Get("http://" + target + h.HttpHealthUrl)
			if errGet == nil {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					err = errors.Errorf("unexpected status %d", resp.StatusCode)
				}
			} else {
				err = errGet
			}
		}
		h.Lock()
		if err != nil {
			h.HealthMap[target]++
			if h.HealthMap[target]%h.HealthMaxFail == 0 {
				hc.serverConn.SendHealthInfo(target, "0")
			}
		} else {
			if h.HealthMap[target] >= h.HealthMaxFail {
				hc.serverConn.SendHealthInfo(target, "1")
			}
			h.HealthMap[target] = 0
		}
		h.Unlock()
	}
}
