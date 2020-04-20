package main

import (
  "github.com/guodf/easy_socks5"
)

func main() {
  server := ServerInterceptor{}
  easy_socks5.Listen(":1080", server)
}

type ServerInterceptor struct {
}

func (ServerInterceptor) SelectMethod(bytes []byte) byte {
  return 0
}
