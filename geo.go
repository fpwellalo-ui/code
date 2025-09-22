package main

import (
        "bufio"
        "crypto/tls"
        "fmt"
        "io"
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
        threads     = 1000
)

// GeoServer mandatory signatures (must have at least one)
var mandatorySignatures = []string{
        "<title>geoserver",
        "geoserver: welcome", 
        "geoserver configuration",
        "org.geoserver.web",
        "geoserver rest api",
        "powered by geoserver",
}

// GeoServer supporting signatures (additional indicators)
var supportingSignatures = []string{
        "geowebcache",
        "wicket:id=\"logo\"",
        "xmlns:wfs=\"http://www.opengis.net/wfs\"",
        "xmlns:wms=\"http://www.opengis.net/wms\"", 
        "xmlns:gml=\"http://www.opengis.net/gml\"",
        "wfs_capabilities",
        "wms_capabilities",
        "wmt_ms_capabilities",
        "service=wfs",
        "service=wms",
        "rest/about/status",
        "rest/about/version",
        "geoserver-logo",
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


func checkGeoServer(url string) (bool, int) {
        confidence := 0
        hasMandatory := false
        supportingMatches := 0

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
                
                // Check for mandatory GeoServer signatures (MUST have at least one)
                for _, sig := range mandatorySignatures {
                        if strings.Contains(bodyStr, sig) {
                                hasMandatory = true
                                confidence += 3 // High weight for mandatory signatures
                                break
                        }
                }
                
                // Check for supporting signatures
                for _, sig := range supportingSignatures {
                        if strings.Contains(bodyStr, sig) {
                                supportingMatches++
                                confidence += 1
                        }
                }

                // Check HTTP headers for GeoServer indicators
                server := strings.ToLower(resp.Header.Get("Server"))
                if strings.Contains(server, "jetty") && hasMandatory {
                        confidence += 2 // Jetty + GeoServer signature
                }

                // Status code bonuses only if we have mandatory signatures
                if hasMandatory {
                        if resp.StatusCode == 200 {
                                confidence += 1
                        } else if (resp.StatusCode == 401 || resp.StatusCode == 403) && strings.Contains(path, "geoserver") {
                                confidence += 2 // Auth-protected GeoServer
                        }
                }
        }

        // STRICT: Must have mandatory signature AND good confidence
        return hasMandatory && confidence >= 5, confidence
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
        mutex.Unlock()

        isFound, _ := checkGeoServer(url)
        if isFound {
                mutex.Lock()
                found++
                fmt.Printf("FOUND %s\n", url)
                
                // Save to file
                file, err := os.OpenFile("found_geoservers.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                if err == nil {
                        file.WriteString(url + "\n")
                        file.Close()
                }
                
                mutex.Unlock()
        }
}

func logProgress() {
        for {
                time.Sleep(1 * time.Second)
                mutex.Lock()
                fmt.Printf("Checked: %d, Found: %d\n", scanned, found)
                mutex.Unlock()
        }
}

func main() {
        // Get port from command line argument
        port := 8080 // default
        if len(os.Args) > 1 {
                if p, err := strconv.Atoi(os.Args[1]); err == nil {
                        port = p
                }
        }
        
        portStr := fmt.Sprintf("%d", port)
        fmt.Printf("GeoServer Scanner - Port %d (paste IPs and press Enter)\n", port)
        fmt.Printf("Found servers will be saved to: found_geoservers.txt\n")
        
        // Start logging immediately
        go logProgress()

        sem := make(chan struct{}, threads)
        var wg sync.WaitGroup
        
        // Stream processing - scan each IP as it comes in
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
                host := strings.TrimSpace(scanner.Text())
                if host == "" || strings.HasPrefix(host, "#") {
                        continue
                }
                
                target := Target{host: host, port: portStr}
                wg.Add(1)
                sem <- struct{}{}
                go scanTarget(target, &wg, sem)
        }

        // Wait for all scans to complete
        wg.Wait()
        fmt.Printf("\nScan complete. Total: %d scanned, %d found\n", scanned, found)
}
