package main

import (
    "bufio"
    "crypto/tls"
    "flag"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"
)

type task struct {
    host string
    port string
}

var (
    defaultPorts     = []string{"80", "443", "8080", "8443", "8081", "8082", "8088", "8000", "8008", "8888", "8181"}
    httpsDefaultSet  = map[string]struct{}{"443": {}, "8443": {}}
    endpoints        = []string{
        "/geoserver/ows?service=WMS&request=GetCapabilities",
        "/geoserver/wfs?service=WFS&request=GetCapabilities",
        "/geoserver/web/",
    }
)

func parsePorts(list string) []string {
    if strings.TrimSpace(list) == "" {
        return defaultPorts
    }
    parts := strings.Split(list, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p == "" {
            continue
        }
        // allow forms like :8080
        p = strings.TrimPrefix(p, ":")
        out = append(out, p)
    }
    return out
}

func schemeForPort(port string) string {
    if _, ok := httpsDefaultSet[port]; ok {
        return "https"
    }
    return "http"
}

func buildBaseURL(scheme, host, port string) string {
    // If host already contains port, don't double-append
    if _, _, err := net.SplitHostPort(host); err == nil {
        return fmt.Sprintf("%s://%s", scheme, host)
    }
    return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

func makeClient(timeout time.Duration, insecure bool) *http.Client {
    transport := &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
        MaxIdleConns:        1000,
        MaxIdleConnsPerHost: 100,
        IdleConnTimeout:     30 * time.Second,
        DisableCompression:  false,
    }
    return &http.Client{Transport: transport, Timeout: timeout}
}

func isGeoServerBody(b []byte) bool {
    s := strings.ToLower(string(b))
    if strings.Contains(s, "geoserver") {
        return true
    }
    if strings.Contains(s, "wms_capabilities") || strings.Contains(s, "wfs_capabilities") {
        return true
    }
    // admin UI
    if strings.Contains(s, "<title>geoserver") || strings.Contains(s, `class="brand">geoserver`) {
        return true
    }
    return false
}

func tryEndpoints(client *http.Client, base string) (bool, string, int) {
    for _, ep := range endpoints {
        u := base + ep
        resp, err := client.Get(u)
        if err != nil {
            // detect wrong scheme and signal to caller by special code
            es := err.Error()
            if strings.Contains(es, "server gave HTTP response to HTTPS client") {
                return false, "scheme-mismatch-https-to-http", 0
            }
            // other transient errors: continue with next endpoint
            continue
        }
        // ensure body close
        func() {
            defer resp.Body.Close()
            // Some servers on HTTPS port when hit via HTTP return 400 with this message
            if resp.StatusCode == 400 {
                // Read small body to inspect
                buf := make([]byte, 2048)
                n, _ := resp.Body.Read(buf)
                body := strings.ToLower(string(buf[:n]))
                if strings.Contains(body, "plain http request was sent to https port") {
                    // signal to caller to swap scheme
                    // return via named values isn't used; set a flag via return tuple
                    // We can't return mid-deferred; pass using outer scope vars via panic is overkill; instead set indicator via status code marker 999
                }
            }
        }()

        // Re-fetch body fully (cheap for small pages) to evaluate quickly
        // Re-do the request with short limit to evaluate body
        resp2, err2 := client.Get(u)
        if err2 != nil {
            continue
        }
        b, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
        resp2.Body.Close()
        if isGeoServerBody(b) {
            return true, u, resp2.StatusCode
        }
        // Some endpoints may be 401/403 but still include GeoServer markers
    }
    return false, "", 0
}

func probeOnce(client *http.Client, scheme, host, port string) (bool, string, int) {
    base := buildBaseURL(scheme, host, port)
    ok, u, sc := tryEndpoints(client, base)
    if ok {
        return true, u, sc
    }
    // handle HTTP->HTTPS mismatch heuristics: if we tried http on 443/8443, just flip
    if scheme == "http" && (port == "443" || port == "8443") {
        base = buildBaseURL("https", host, port)
        ok, u, sc = tryEndpoints(client, base)
        if ok {
            return true, u, sc
        }
    }
    // best-effort flip if first try failed on typical HTTPS ports detection via 400 text handled above is tricky across requests; simply try the other scheme once on mismatch ports
    if scheme == "http" {
        base = buildBaseURL("https", host, port)
        ok, u, sc = tryEndpoints(client, base)
        if ok {
            return true, u, sc
        }
    } else {
        base = buildBaseURL("http", host, port)
        ok, u, sc = tryEndpoints(client, base)
        if ok {
            return true, u, sc
        }
    }
    return false, "", 0
}

func main() {
    var (
        portsFlag      string
        concurrency    int
        timeoutSec     int
        insecureTLS    bool
        outPath        string
        outFormat      string
        outAppend      bool
    )
    flag.StringVar(&portsFlag, "ports", strings.Join(defaultPorts, ","), "Comma-separated ports to scan")
    flag.IntVar(&concurrency, "concurrency", 200, "Number of concurrent workers")
    flag.IntVar(&timeoutSec, "timeout", 3, "Per-request timeout in seconds")
    flag.BoolVar(&insecureTLS, "insecure", true, "Skip TLS certificate verification")
    flag.StringVar(&outPath, "out", "", "Write results to file (optional)")
    flag.StringVar(&outFormat, "format", "txt", "Output format: txt|csv|jsonl")
    flag.BoolVar(&outAppend, "append", true, "Append to output file if exists")
    flag.Parse()

    // Prepare target hosts from stdin
    info, _ := os.Stdin.Stat()
    if info.Mode()&os.ModeCharDevice != 0 {
        fmt.Fprintln(os.Stderr, "Provide hosts via stdin, one per line. Example: cat hosts.txt | geoserver_finder -concurrency 200")
        os.Exit(2)
    }

    scanner := bufio.NewScanner(os.Stdin)
    scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

    ports := parsePorts(portsFlag)
    timeout := time.Duration(timeoutSec) * time.Second
    client := makeClient(timeout, insecureTLS)

    var wg sync.WaitGroup
    foundMu := &sync.Mutex{}
    found := make(map[string]struct{})

    // Optional output file
    var outFile *os.File
    var outWriter *bufio.Writer
    fileMu := &sync.Mutex{}
    if strings.TrimSpace(outPath) != "" {
        flags := os.O_CREATE | os.O_WRONLY
        if outAppend {
            flags |= os.O_APPEND
        } else {
            flags |= os.O_TRUNC
        }
        f, err := os.OpenFile(outPath, flags, 0644)
        if err != nil {
            fmt.Fprintf(os.Stderr, "failed to open out file: %v\n", err)
            os.Exit(1)
        }
        outFile = f
        outWriter = bufio.NewWriter(outFile)
        defer func() {
            outWriter.Flush()
            outFile.Close()
        }()
    }

    writeResult := func(u string, host string, port string, status int) {
        if outWriter == nil {
            return
        }
        line := ""
        switch strings.ToLower(outFormat) {
        case "csv":
            // url,host,port,status
            line = fmt.Sprintf("%s,%s,%s,%d\n", u, host, port, status)
        case "jsonl":
            // minimal JSON per line
            // escape quotes in URL minimally
            esc := strings.ReplaceAll(u, "\"", "\\\"")
            line = fmt.Sprintf("{\"url\":\"%s\",\"host\":\"%s\",\"port\":\"%s\",\"status\":%d}\n", esc, host, port, status)
        default: // txt
            line = u + "\n"
        }
        fileMu.Lock()
        outWriter.WriteString(line)
        fileMu.Unlock()
    }

    runTask := func(t task) {
        sch := schemeForPort(t.port)
        ok, hit, sc := probeOnce(client, sch, t.host, t.port)
        if ok {
            foundMu.Lock()
            if _, seen := found[hit]; !seen {
                found[hit] = struct{}{}
                fmt.Printf("FOUND %s\n", hit)
                writeResult(hit, t.host, t.port, sc)
            }
            foundMu.Unlock()
        }
    }

    if concurrency == 0 { // stream: unlimited goroutines per task
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line == "" {
                continue
            }
            // Normalize input: accept URL or host[:port]
            input := line
            if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
                if u, err := url.Parse(line); err == nil && u.Host != "" {
                    input = u.Host
                }
            }
            if host, port, err := net.SplitHostPort(input); err == nil && port != "" {
                wg.Add(1)
                go func(h, p string) { defer wg.Done(); runTask(task{host: h, port: p}) }(host, port)
            } else {
                for _, p := range ports {
                    wg.Add(1)
                    go func(h, p string) { defer wg.Done(); runTask(task{host: h, port: p}) }(input, p)
                }
            }
        }
        wg.Wait()
        return
    }

    // Bounded worker pool with streaming input
    if concurrency < 1 {
        concurrency = 1
    }
    if concurrency > 5000 {
        concurrency = 5000
    }

    tasksCh := make(chan task, 4096)
    var workersWG sync.WaitGroup
    var tasksWG sync.WaitGroup
    workersWG.Add(concurrency)
    for i := 0; i < concurrency; i++ {
        go func() {
            defer workersWG.Done()
            for t := range tasksCh {
                runTask(t)
                tasksWG.Done()
            }
        }()
    }
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }
        input := line
        if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
            if u, err := url.Parse(line); err == nil && u.Host != "" {
                input = u.Host
            }
        }
        if host, port, err := net.SplitHostPort(input); err == nil && port != "" {
            tasksWG.Add(1)
            tasksCh <- task{host: host, port: port}
        } else {
            for _, p := range ports {
                tasksWG.Add(1)
                tasksCh <- task{host: input, port: p}
            }
        }
    }
    close(tasksCh)
    tasksWG.Wait()
    workersWG.Wait()
}
