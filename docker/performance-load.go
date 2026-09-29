// 本地性能夹具：同一源站和负载实现服务 TCP、HTTPS 与 HTTP/2。
// 不属于产品运行时代码；套接字计数位于 TLS 下层，用于核对隧道真实字节。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var block = bytes.Repeat([]byte("x"), 65536)

type countedConn struct {
	net.Conn
	read, written *atomic.Int64
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, e
}
func (c *countedConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, e
}

func (c *countedConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

type countedListener struct {
	net.Listener
	read, written *atomic.Int64
}

func (l countedListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &countedConn{c, l.read, l.written}, nil
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func listener(addr string, r, w *atomic.Int64) net.Listener {
	l, e := net.Listen("tcp", addr)
	must(e)
	return countedListener{l, r, w}
}
func payload(w io.Writer, n int64) error {
	for n > 0 {
		b := block
		if n < int64(len(b)) {
			b = b[:n]
		}
		sent, e := w.Write(b)
		n -= int64(sent)
		if e != nil {
			return e
		}
		if sent == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func origin(cert, key string) {
	var read, written atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, e := strconv.ParseInt(r.URL.Path[1:], 10, 64)
		if e != nil || n < 1 || n > 1<<30 {
			http.Error(w, "长度无效", 400)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/octet-stream")
		_ = payload(w, n)
	})
	go func() { must(http.Serve(listener(":18080", &read, &written), handler)) }()
	go func() {
		s := &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}}
		must(s.ServeTLS(listener(":18443", &read, &written), cert, key))
	}()
	go func() {
		l := listener(":18081", &read, &written)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				var h [8]byte
				for {
					if _, e := io.ReadFull(c, h[:]); e != nil {
						return
					}
					n := binary.BigEndian.Uint64(h[:])
					if n > 1<<30 {
						return
					}
					if payload(c, int64(n)) != nil {
						return
					}
				}
			}()
		}
	}()
	must(http.ListenAndServe(":18082", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]int64{"read": read.Load(), "written": written.Load()})
	})))
}

// 直方图保留每轮全部请求的计数，精度为 10 微秒，避免高 QPS 时记录日志成为瓶颈。
type histogram map[int64]int64

func (h histogram) add(d time.Duration) { h[d.Microseconds()/10]++ }

type result struct {
	Requests       int64            `json:"requests"`
	Errors         map[string]int64 `json:"errors"`
	Latency        histogram        `json:"latency_10us"`
	Connect        histogram        `json:"connect_10us"`
	Handshake      histogram        `json:"handshake_10us"`
	TTFB           histogram        `json:"ttfb_10us"`
	Reused         int64            `json:"reused_connections"`
	Resumed        int64            `json:"resumed_sessions"`
	TLS            map[string]int64 `json:"tls"`
	Protocols      map[string]int64 `json:"protocols"`
	MeasuredBytes  int64            `json:"measured_bytes"`
	TotalBytes     int64            `json:"total_bytes"`
	CompletedBytes int64            `json:"completed_bytes"`
	Kind           string           `json:"kind"`
}

func newResult(kind string) result {
	return result{Errors: map[string]int64{}, Latency: histogram{}, Connect: histogram{}, Handshake: histogram{}, TTFB: histogram{}, TLS: map[string]int64{}, Protocols: map[string]int64{}, Kind: kind}
}

// 在固定测量窗口内累计已收到且逐字节验证的有效载荷，排除预热和收尾字节。
func readPayload(r io.Reader, n int64, buf []byte, begin, end time.Time, out *result) error {
	var count int64
	for count < n {
		b := buf
		if int64(len(b)) > n-count {
			b = b[:n-count]
		}
		got, e := r.Read(b)
		if !bytes.Equal(b[:got], block[:got]) {
			return fmt.Errorf("响应内容不一致")
		}
		count += int64(got)
		out.TotalBytes += int64(got)
		now := time.Now()
		if !now.Before(begin) && now.Before(end) {
			out.MeasuredBytes += int64(got)
		}
		if e != nil {
			if e == io.EOF && count == n {
				break
			}
			return e
		}
		if got == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func load(addr, host, ca, protocol, workload, mode string, concurrency, bulkMiB int, warm, duration float64) {
	caPEM, e := os.ReadFile(ca)
	must(e)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		panic("测试 CA 无效")
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	var clientConnections atomic.Int64
	var wireRead, wireWritten atomic.Int64
	if mode == "resume" {
		tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(128)
	}
	newTransport := func() *http.Transport {
		return &http.Transport{
			Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: protocol == "h2", DisableCompression: true,
			DisableKeepAlives: mode == "fresh" || mode == "resume", MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
				if err == nil {
					clientConnections.Add(1)
				}
				if err != nil {
					return nil, err
				}
				return &countedConn{conn, &wireRead, &wireWritten}, nil
			},
		}
	}
	var begin, end time.Time
	var shared *http.Transport
	if protocol == "h2" {
		shared = newTransport()
		defer shared.CloseIdleConnections()
		// 先建立唯一 H2 连接，后续 worker 只复用它，避免并发首次拨号产生多条连接。
		client := &http.Client{Transport: shared, Timeout: 30 * time.Second}
		r, e := client.Get("https://" + host + "/1024")
		must(e)
		_, e = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		must(e)
		if r.ProtoMajor != 2 {
			panic("未协商 HTTP/2")
		}
	}
	// H2 预建连接不占用指定的预热时长，慢链路不能挤掉正式测量窗口。
	begin = time.Now().Add(time.Duration(warm * float64(time.Second)))
	end = begin.Add(time.Duration(duration * float64(time.Second)))
	workers := concurrency
	if workload == "mixed" {
		workers *= 2
	}
	results := make([]result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			short := workload == "short" || (workload == "mixed" && i >= concurrency)
			n := int64(bulkMiB) << 20
			kind := "bulk"
			if short {
				n = 1024
				kind = "short"
			}
			out := newResult(kind)
			buf := make([]byte, 65536)
			var raw net.Conn
			var reader *bufio.Reader
			transport := shared
			if transport == nil {
				transport = newTransport()
				defer transport.CloseIdleConnections()
			}
			client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
			defer func() {
				if raw != nil {
					raw.Close()
				}
				results[i] = out
			}()
			for time.Now().Before(end) {
				started := time.Now()
				measured := !started.Before(begin)
				var err error
				if protocol == "tcp" {
					if raw == nil {
						raw, err = net.DialTimeout("tcp", addr, 10*time.Second)
						if err == nil {
							clientConnections.Add(1)
							raw = &countedConn{raw, &wireRead, &wireWritten}
							reader = bufio.NewReader(raw)
						}
					}
					if err == nil {
						raw.SetDeadline(time.Now().Add(30 * time.Second))
						var h [8]byte
						binary.BigEndian.PutUint64(h[:], uint64(n))
						_, err = raw.Write(h[:])
						if err == nil {
							err = readPayload(reader, n, buf, begin, end, &out)
						}
					}
				} else {
					var connectAt, tlsAt time.Time
					var connect, tlsElapsed, ttfb time.Duration
					var reused, resumed bool
					var version, cipher uint16
					trace := &httptrace.ClientTrace{ConnectStart: func(_, _ string) { connectAt = time.Now() }, ConnectDone: func(_, _ string, _ error) { connect = time.Since(connectAt) }, TLSHandshakeStart: func() { tlsAt = time.Now() }, TLSHandshakeDone: func(s tls.ConnectionState, _ error) {
						tlsElapsed = time.Since(tlsAt)
						resumed = s.DidResume
						version = s.Version
						cipher = s.CipherSuite
					}, GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }, GotFirstResponseByte: func() { ttfb = time.Since(started) }}
					req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", "https://"+host+"/"+strconv.FormatInt(n, 10), nil)
					req.Header.Set("Accept-Encoding", "identity")
					var response *http.Response
					response, err = client.Do(req)
					if err == nil {
						if response.StatusCode != 200 || response.ContentLength != n || response.Header.Get("Content-Encoding") != "" {
							err = fmt.Errorf("状态/长度/编码不匹配: %d/%d", response.StatusCode, response.ContentLength)
						}
						if (protocol == "h2" && response.ProtoMajor != 2) || (protocol == "h1" && response.ProtoMajor != 1) {
							err = fmt.Errorf("协议不匹配: %s", response.Proto)
						}
						if err == nil {
							err = readPayload(response.Body, n, buf, begin, end, &out)
						}
						response.Body.Close()
						if measured {
							out.Protocols[response.Proto]++
							if response.TLS != nil {
								version = response.TLS.Version
								cipher = response.TLS.CipherSuite
							}
						}
					}
					if measured {
						if connect > 0 {
							out.Connect.add(connect)
						}
						if tlsElapsed > 0 {
							out.Handshake.add(tlsElapsed)
						}
						if ttfb > 0 {
							out.TTFB.add(ttfb)
						}
						if reused {
							out.Reused++
						}
						if resumed {
							out.Resumed++
						}
						out.TLS[fmt.Sprintf("%x/%s", version, tls.CipherSuiteName(cipher))]++
					}
				}
				if measured {
					if err != nil {
						out.Errors[err.Error()]++
					} else {
						out.Requests++
						out.Latency.add(time.Since(started))
						out.CompletedBytes += n
					}
				}
				if err != nil {
					if raw != nil {
						raw.Close()
						raw = nil
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			if protocol == "tcp" && raw != nil {
				// 所有完整响应读完后半关闭，请求方向 EOF 必须能穿透隧道，且不能凭空增加数据。
				raw.(*countedConn).CloseWrite()
				raw.SetReadDeadline(time.Now().Add(10 * time.Second))
				var b [1]byte
				n, e := reader.Read(b[:])
				if n != 0 || e != io.EOF {
					out.Errors["TCP 半关闭未正常结束"]++
				}
			}
		}(i)
	}
	wg.Wait()
	if shared != nil {
		shared.CloseIdleConnections()
	}
	setupBytes := 0
	if protocol == "h2" {
		setupBytes = 1024
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"warm_seconds": warm, "measure_seconds": duration, "drain_seconds": time.Since(end).Seconds(), "workers": results, "histogram_resolution_us": 10, "client_connections": clientConnections.Load(), "wire_read": wireRead.Load(), "wire_written": wireWritten.Load(), "setup_payload_bytes": setupBytes, "bulk_mib": bulkMiB}))
}

func main() {
	role := flag.String("role", "load", "origin 或 load")
	cert := flag.String("cert", "", "证书")
	key := flag.String("key", "", "私钥")
	ca := flag.String("ca", "", "CA")
	addr := flag.String("addr", "", "目标地址")
	host := flag.String("host", "secure.nexo-smoke.localhost", "TLS 名称")
	protocol := flag.String("protocol", "h1", "tcp/h1/h2")
	workload := flag.String("workload", "short", "bulk/short/mixed")
	mode := flag.String("mode", "keepalive", "keepalive/fresh/resume")
	concurrency := flag.Int("concurrency", 1, "并发")
	bulkMiB := flag.Int("bulk-mib", 64, "每个大文件响应的 MiB，避免小对象请求往返主导吞吐")
	warm := flag.Float64("warm", 5, "预热秒数")
	duration := flag.Float64("duration", 15, "测量秒数")
	flag.Parse()
	if *role == "origin" {
		origin(*cert, *key)
	} else {
		if *bulkMiB < 1 || *bulkMiB > 1024 {
			panic("bulk-mib 必须介于 1 和 1024")
		}
		load(*addr, *host, *ca, *protocol, *workload, *mode, *concurrency, *bulkMiB, *warm, *duration)
	}
}
