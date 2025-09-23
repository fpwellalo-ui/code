#!/usr/bin/env python3
"""
High-Performance GeoServer Checker
Читает IP:port из файла и проверяет на GeoServer с максимальной скоростью
"""

import json
import time
import threading
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from colorama import init, Fore, Style
import urllib3

# Отключаем SSL warnings для скорости
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


class HighPerformanceGeoChecker:

    def __init__(self):
        self.results = []
        self.lock = threading.Lock()
        self.stats = {
            'checked': 0,
            'geoservers_found': 0,
            'errors': 0,
            'start_time': None
        }

        # Настройки производительности (более консервативные)
        self.max_threads = 200  # Умеренное количество потоков
        self.timeout = 3  # Умеренный таймаут
        self.max_retries = 1  # Минимум повторов

        # GeoServer эндпоинты (приоритетные первыми)
        self.endpoints = [
            "/geoserver/web/",  # Самый надежный
            "/geoserver/",
            "/geoserver/rest/about/version"
        ]

        # Сигнатуры GeoServer (быстрая проверка)
        self.signatures = [
            b'geoserver', b'opengeo', b'geowebcache', b'getcapabilities'
        ]

        # Заголовки для обхода блокировок
        self.headers = {
            'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept':
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close'
        }

    def load_targets(self, filename):
        """Загрузка IP:port из файла masscan"""
        targets = []

        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Формат masscan: open tcp 80 192.168.1.1 timestamp
                    if line.startswith('open tcp'):
                        parts = line.split()
                        if len(parts) >= 4:
                            port = int(parts[2])
                            host = parts[3]
                            targets.append((host, port))

                    # Формат IP:port
                    elif ':' in line:
                        try:
                            host, port = line.split(':')
                            targets.append((host.strip(), int(port.strip())))
                        except:
                            continue

            print(f"{Fore.GREEN}[+] Загружено {len(targets)} целей")
            return targets

        except FileNotFoundError:
            print(f"{Fore.RED}[!] Файл {filename} не найден")
            return []
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка загрузки: {e}")
            return []

    def check_geoserver_fast(self, host, port):
        """Быстрая проверка на GeoServer"""
        schemes = [
            'http'
        ] if port == 80 else ['https'] if port == 443 else ['http', 'https']

        for scheme in schemes:
            base_url = f"{scheme}://{host}:{port}"

            # Проверяем только самый надежный эндпоинт для скорости
            for endpoint in self.endpoints[:1]:  # Только первый
                try:
                    url = urljoin(base_url, endpoint)

                    response = requests.get(url,
                                            timeout=self.timeout,
                                            verify=False,
                                            headers=self.headers,
                                            stream=False,
                                            allow_redirects=False)

                    if self.is_geoserver_fast(response):
                        return {
                            'host': host,
                            'port': port,
                            'url': base_url
                        }

                except Exception:
                    continue

        return None

    def is_geoserver_fast(self, response):
        """Быстрая проверка на GeoServer по байтам"""
        if response.status_code not in [200, 401, 403]:
            return False

        # Читаем только первые 2KB для скорости
        content = response.content[:2048].lower()
        return any(sig in content for sig in self.signatures)

    def extract_version(self, content):
        """Быстрое извлечение версии"""
        try:
            # Смотрим только первые 4KB
            text = content[:4096].decode('utf-8', errors='ignore').lower()

            patterns = [
                rb'geoserver\s+(\d+\.\d+[\.\d]*)',
                rb'version[>\s]+(\d+\.\d+[\.\d]*)'
            ]

            for pattern in patterns:
                match = re.search(pattern, content[:1024])  # Только начало
                if match:
                    return match.group(1).decode('utf-8', errors='ignore')

        except:
            pass

        return "Unknown"

    def scan_targets(self, targets):
        """Стабильное сканирование всех целей"""
        if not targets:
            print(f"{Fore.RED}[!] Нет целей для проверки")
            return

        # Очищаем файлы результатов
        open("geoservers_found_live.json", "w").close()
        open("geoservers_simple_live.txt", "w").close()
        print(f"{Fore.GREEN}[+] Созданы файлы для живой записи результатов:")
        print(f"{Fore.GREEN}    - geoservers_found_live.json")
        print(f"{Fore.GREEN}    - geoservers_simple_live.txt")

        print(f"{Fore.YELLOW}[*] Начинаем проверку {len(targets)} целей...")
        print(
            f"{Fore.CYAN}[*] Потоков: {self.max_threads}, таймаут: {self.timeout}s"
        )

        self.stats['start_time'] = time.time()
        total_targets = len(targets)
        batch_size = 10000  # Обрабатываем батчами для стабильности

        # Обрабатываем цели батчами
        for batch_start in range(0, total_targets, batch_size):
            batch_end = min(batch_start + batch_size, total_targets)
            batch_targets = targets[batch_start:batch_end]

            print(
                f"{Fore.YELLOW}[*] Обрабатываем батч {batch_start+1}-{batch_end} из {total_targets}"
            )

            try:
                # Обрабатываем батч с ThreadPool
                with ThreadPoolExecutor(
                        max_workers=self.max_threads) as executor:
                    future_to_target = {
                        executor.submit(self.check_geoserver_fast, host, port):
                        (host, port)
                        for host, port in batch_targets
                    }

                    # Обрабатываем результаты по мере готовности
                    completed = 0
                    for future in as_completed(future_to_target):
                        try:
                            future.result(timeout=self.timeout + 2)
                        except Exception as e:
                            with self.lock:
                                self.stats['errors'] += 1

                        completed += 1

                        # Показываем прогресс каждые 100 проверок
                        if completed % 100 == 0:
                            elapsed = time.time() - self.stats['start_time']
                            speed = self.stats[
                                'checked'] / elapsed if elapsed > 0 else 0
                            print(
                                f"{Fore.BLUE}[*] Проверено: {self.stats['checked']}/{total_targets} "
                                f"(~{speed:.0f}/сек, найдено: {self.stats['geoservers_found']})"
                            )

                # Небольшая пауза между батчами для стабильности
                time.sleep(1)

            except Exception as e:
                print(
                    f"{Fore.RED}[!] Ошибка в батче {batch_start+1}-{batch_end}: {e}"
                )
                # Продолжаем с следующим батчем
                continue

        print(
            f"{Fore.GREEN}[+] Обработка всех {total_targets} целей завершена!")

    def print_stats(self):
        """Статистика работы"""
        elapsed = time.time(
        ) - self.stats['start_time'] if self.stats['start_time'] else 0
        speed = self.stats['checked'] / elapsed if elapsed > 0 else 0

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}РЕЗУЛЬТАТЫ ВЫСОКОПРОИЗВОДИТЕЛЬНОЙ ПРОВЕРКИ")
        print(f"{Fore.CYAN}{'='*60}")
        print(
            f"{Fore.GREEN}Найдено GeoServer'ов: {self.stats['geoservers_found']}"
        )
        print(f"{Fore.YELLOW}Проверено хостов: {self.stats['checked']}")
        print(f"{Fore.YELLOW}Ошибок: {self.stats['errors']}")
        print(f"{Fore.YELLOW}Время работы: {elapsed:.1f} сек")
        print(f"{Fore.YELLOW}Скорость: {speed:.0f} проверок/сек")

        if self.results:
            # Статистика версий
            versions = {}
            for r in self.results:
                v = r['version']
                versions[v] = versions.get(v, 0) + 1

            print(f"\n{Fore.CYAN}Версии найденных GeoServer'ов:")
            for version, count in sorted(versions.items()):
                print(f"  {version}: {count}")

            print(f"\n{Fore.CYAN}Примеры найденных серверов:")
            for r in self.results[:10]:
                print(f"  {r['url']} (v{r['version']})")

    def save_results(self, filename="geoservers_found.json"):
        """Сохранение результатов в JSON"""
        if self.results:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"{Fore.GREEN}[+] Детальные результаты: {filename}")
        else:
            print(f"{Fore.RED}[!] GeoServer'ы не найдены")

    def save_live_result(self, result):
        """Сохранение результата сразу при обнаружении"""
        try:
            # Записываем в JSON файл
            with open("geoservers_found_live.json", "a") as f:
                json.dump(result, f)
                f.write("\n")

            # Записываем в простой список
            with open("geoservers_simple_live.txt", "a") as f:
                f.write(f"{result['host']}:{result['port']}\n")

            # Принудительно сбрасываем буферы
            import os
            os.sync()
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка записи результата: {e}")

    def save_simple_results(self, filename="geoservers_simple.txt"):
        """Сохранение только IP:port"""
        if self.results:
            with open(filename, 'w') as f:
                for result in self.results:
                    f.write(f"{result['host']}:{result['port']}\n")
            print(f"{Fore.GREEN}[+] Простой список IP:port: {filename}")
        else:
            print(f"{Fore.RED}[!] GeoServer'ы не найдены")


def process_target(line, port, checker):
    """Обрабатывает одну цель из stdin"""
    try:
        ip = line.strip()
        if not ip:
            return
        
        result = checker.check_geoserver_fast(ip, port)
        if result:
            print(f"[FOUND]: {ip}:{port}")
    except Exception:
        pass

def main():
    import sys
    import os
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    if len(sys.argv) != 2:
        print("Usage: zmap -p 80 | python3 scan.py 80")
        print("Usage: echo 'IP_ADDRESS' | python3 scan.py PORT")  
        sys.exit(1)
    
    try:
        port = int(sys.argv[1])
    except:
        print("Port must be a number")
        sys.exit(1)
    
    checker = HighPerformanceGeoChecker()
    checker.max_threads = 500  # Больше потоков для stdin
    
    # Читаем из stdin как main.go
    try:
        with ThreadPoolExecutor(max_workers=checker.max_threads) as executor:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    executor.submit(process_target, line, port, checker)
                    
    except KeyboardInterrupt:
        print("\nStopped by user")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
