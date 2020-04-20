package main

import (
  "net"

  "github.com/guodf/easy_socks5"
)

func main() {
  client := ClientInterceptor{}
  easy_socks5.Dial("localhost:1080", client)
}

type ClientInterceptor struct {
}

func (c ClientInterceptor) Connected(conn net.Conn) {
  conn.Write([]byte("hello"))
}
