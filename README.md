# easy_socks5
```go
# client
func main() {
  client := ClientInterceptor{}
  easy_socks5.Dial("localhost:1080", client)
}

type ClientInterceptor struct {
}

func (c ClientInterceptor) Connected(conn net.Conn) {
  conn.Write([]byte("hello"))
}
```

```go
# server
func main() {
  server := ServerInterceptor{}
  easy_socks5.Listen(":1080", server)
}

type ServerInterceptor struct {
}

func (ServerInterceptor) SelectMethod(bytes []byte) byte {
  return 0
}

```
