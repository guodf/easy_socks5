package easy_socks5

import (
  "encoding/binary"
  "errors"
  "log"
  "net"
  "strconv"
  "strings"
)

type IServerInterceptor interface {
  SelectMethod([]byte) byte
}

type IClientInterceptor interface {
  Connected(rw net.Conn)
}

// 启动失败
var ListenErr = errors.New("listen start failed")
var ConnErr = errors.New("conn server failed")
var HandlesErr = errors.New("socks5 valid failed")

func Listen(network string, server IServerInterceptor) error {
  l, e := net.Listen("tcp", network)
  if e != nil {
    log.Println(e)
    return ListenErr
  }
  for {
    c, e := l.Accept()
    if e != nil {
      continue
    }
    go start(c, server)
  }
}

func start(c net.Conn, server IServerInterceptor) {
  defer c.Close()
  socks5 := NewSocks5(c)

  if !socks5.Valid() {
    return
  }
  methods, e := socks5.GetMethods()
  if e != nil {
    return
  }
  method := server.SelectMethod(methods)
  socks5.ReplyAsk(method)
  if !socks5.ValidConn() {
    return
  }
  addr, e := socks5.GetAddr()
  if e != nil {
    return
  }
  log.Println(addr)
  rc, e := net.Dial("tcp", addr)
  if e != nil {
    socks5.ReplyConn(REP_4)
    return
  }
  defer rc.Close()
  e = socks5.ReplyConn(REP_0)
  if e != nil {
    return
  }
  go socks5.Exchange(rc)
}

func Dial(network string, client IClientInterceptor) error {
  c, e := net.Dial("tcp", network)
  if e != nil {
    return ConnErr
  }
  network = "baidu.com:443"
  addrArr := strings.Split(network, ":")
  socks5 := NewSocks5(c)
  if strings.ToLower(addrArr[0]) == "localhost" {
    socks5.SetAddr(net.ParseIP("127.0.0.1"))
    socks5.SetATYP(ATYP_IPV4)
  } else {
    ip := net.ParseIP(addrArr[0])
    if ip == nil {
      socks5.SetAddr([]byte(addrArr[0]))
      socks5.SetATYP(ATYP_DOMAINNAME)
    } else {
      if len(ip.To4()) == net.IPv4len {
        socks5.SetAddr(ip.To4())
        socks5.SetATYP(ATYP_IPV4)
      } else {
        socks5.SetAddr(ip.To16())
        socks5.SetATYP(ATYP_IPV6)
      }
    }
  }
  port, _ := strconv.Atoi(addrArr[1])
  portBytes := make([]byte, 2)
  binary.BigEndian.PutUint16(portBytes, uint16(port))
  socks5.SetPort(portBytes)

  if socks5.Ask() {
    if socks5.Conn(CMD_CONNECT) {
      client.Connected(socks5.conn)
      return nil
    }
  }
  return HandlesErr
}
