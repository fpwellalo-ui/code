package main

import (
        "bufio"
        "crypto/tls"
        "flag"
        "fmt"
        "io"
        "math/rand"
        "net"
        "net/http"
        "os"
        "strconv"
        "strings"
        "sync"
        "time"
)

var (
        found       int
        scanned     int
        mutex       sync.Mutex
        client      *http.Client
        outputFile  *os.File
        
        // Command line flags
        threads     = flag.Int("t", 1000, "Number of threads")
        port        = flag.Int("p", 8080, "Port to scan")
        generateIPs = flag.Bool("g", false, "Generate random IPs instead of reading from stdin")
        rangeCount  = flag.Int("r", 10000, "Number of random IPs to generate when -g is used")
)

// GeoServer signatures
var signatures = []string{
        "geoserver: welcome",
        "<title>geoserver",
        "geoserver configuration",
        "xmlns:wfs=\"http://www.opengis.net/wfs\"",
        "xmlns:gml=\"http://www.opengis.net/gml\"",
        "getcapabilities",
        "geowebcache",
        "wicket:id=\"logo\"",
        "wfs_capabilities",
        "wmt_ms_capabilities",
        "geoserver-logo",
        "rest/about/status",
        "opengis.net",
}

// GeoServer paths
var paths = []string{
        "/geoserver/",
        "/geoserver/web/",
        "/geoserver/rest/",
        "/geoserver/wms?request=GetCapabilities",
        "/geoserver/wfs?request=GetCapabilities",
        "/geoserver/ows?service=WMS&request=GetCapabilities",
        "/geoserver/rest/about/status",
        "/",
}

type Target struct {
        host string
        port string
}

func init() {
        client = &http.Client{
                Timeout: 8 * time.Second,
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                        DialContext: (&net.Dialer{
                                Timeout: 3 * time.Second,
                        }).DialContext,
                        MaxIdleConns:        100,
                        MaxIdleConnsPerHost: 10,
                        IdleConnTimeout:     10 * time.Second,
                },
        }
}

func generateRandomIP() string {
        // Generate random public IP ranges
        for {
                a := rand.Intn(256)
                b := rand.Intn(256)
                c := rand.Intn(256)
                d := rand.Intn(256)
                
                // Skip private/reserved ranges
                if a == 10 || a == 127 || a == 169 || a == 172 || a == 192 || a == 0 || a >= 224 {
                        continue
                }
                
                return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
        }
}

func checkGeoServer(url string) (bool, int) {
        confidence := 0
        
        for _, path := range paths {
                testURL := url + path
                
                req, err := http.NewRequest("GET", testURL, nil)
                if err != nil {
                        continue
                }
                
                req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                req.Header.Set("Accept", "text/html,application/xml,*/*")
                
                resp, err := client.Do(req)
                if err != nil {
                        continue
                }
                
                body, err := io.ReadAll(resp.Body)
                resp.Body.Close()
                if err != nil {
                        continue
                }
                
                bodyStr := strings.ToLower(string(body))
                
                // Count signature matches
                sigMatches := 0
                for _, sig := range signatures {
                        if strings.Contains(bodyStr, sig) {
                                sigMatches++
                        }
                }
                
                if sigMatches >= 3 {
                        confidence += 4
                } else if sigMatches >= 1 {
                        confidence += sigMatches
                }
                
                // Status code bonus
                if resp.StatusCode == 200 && sigMatches > 0 {
                        confidence += 2
                } else if (resp.StatusCode == 401 || resp.StatusCode == 403) && strings.Contains(path, "geoserver") {
                        confidence += 1
                }
        }
        
        return confidence >= 3, confidence
}

func scanTarget(target Target, wg *sync.WaitGroup, sem chan struct{}) {
        defer wg.Done()
        defer func() { <-sem }()
        
        // Determine protocol based on port
        protocol := "http"
        if target.port == "443" {
                protocol = "https"
        }
        
        url := fmt.Sprintf("%s://%s:%s", protocol, target.host, target.port)
        
        mutex.Lock()
        scanned++
        currentScanned := scanned
        mutex.Unlock()
        
        isFound, confidence := checkGeoServer(url)
        if isFound {
                mutex.Lock()
                found++
                status := "FOUND"
                if confidence >= 6 {
                        status = "CONFIRMED"
                } else if confidence >= 4 {
                        status = "LIKELY"
                }
                fmt.Printf("🔥 [%s] %s (confidence: %d)\n", status, url, confidence)
                
                // Save to file
                if outputFile != nil {
                        outputFile.WriteString(fmt.Sprintf("%s\n", url))
                        outputFile.Sync()
                }
                mutex.Unlock()
        }
        
        if currentScanned%200 == 0 {
                mutex.Lock()
                fmt.Printf("📊 Progress: %d scanned, %d found\n", currentScanned, found)
                mutex.Unlock()
        }
}

func main() {
        flag.Parse()
        
        // Create output file for found GeoServers
        var err error
        outputFile, err = os.Create("found_geoservers.txt")
        if err != nil {
                fmt.Printf("❌ Error creating output file: %v\n", err)
                os.Exit(1)
        }
        defer outputFile.Close()
        
        fmt.Printf("🚀 GeoServer Scanner v2.0\n")
        fmt.Printf("🔍 Port: %d | Threads: %d\n", *port, *threads)
        if *generateIPs {
                fmt.Printf("🎲 Mode: Random IP generation (%d IPs)\n", *rangeCount)
        } else {
                fmt.Printf("📋 Mode: Reading from stdin\n")
        }
        fmt.Printf("💾 Output file: found_geoservers.txt\n")
        fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        var targets []Target
        portStr := strconv.Itoa(*port)
        
        if *generateIPs {
                // Generate random IPs
                rand.Seed(time.Now().UnixNano())
                for i := 0; i < *rangeCount; i++ {
                        ip := generateRandomIP()
                        targets = append(targets, Target{host: ip, port: portStr})
                }
        } else {
                // Read from stdin
                scanner := bufio.NewScanner(os.Stdin)
                for scanner.Scan() {
                        host := strings.TrimSpace(scanner.Text())
                        if host == "" || strings.HasPrefix(host, "#") {
                                continue
                        }
                        targets = append(targets, Target{host: host, port: portStr})
                }
                
                if len(targets) == 0 {
                        fmt.Println("❌ No targets. Usage:")
                        fmt.Println("  echo 'site.com' | ./geoscan -p 8080 -t 1000")
                        fmt.Println("  ./geoscan -g -r 5000 -p 80 -t 2000")
                        os.Exit(1)
                }
        }
        
        fmt.Printf("🎯 Scanning %d targets on port %d\n", len(targets), *port)
        
        sem := make(chan struct{}, *threads)
        var wg sync.WaitGroup
        
        start := time.Now()
        
        for _, target := range targets {
                wg.Add(1)
                sem <- struct{}{}
                go scanTarget(target, &wg, sem)
        }
        
        wg.Wait()
        elapsed := time.Since(start)
        
        fmt.Printf("\n🏁 Scan complete in %v\n", elapsed)
        fmt.Printf("📊 Total: %d scanned, %d found\n", scanned, found)
        fmt.Printf("🚀 Speed: %.0f req/sec\n", float64(scanned)/elapsed.Seconds())
        if found > 0 {
                fmt.Printf("💾 Results saved to: found_geoservers.txt\n")
        }
}
