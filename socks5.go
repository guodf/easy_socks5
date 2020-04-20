package easy_socks5

import (
  "bufio"
  "encoding/binary"
  "fmt"
  "io"
  "log"
  "net"
)

//								socks v5
//  https://tools.ietf.org/html/rfc1928
// socket握手分两个阶段: 1. 客户端列举自己的密码模式供服务端选择，2. 客户端发起握手连接
//	1. 客户端列举自己的密码模式供服务端选择
//			+----+----------+----------+
//			|VER | NMETHODS | METHODS  |
//			+----+----------+----------+
//			| 1  |    1     | 1 to 255 |
//			+----+----------+----------+
// VER: 0x05
// NMETHODS: METHODS字节数
// METHODS: 密码模式
//		  0x00 NO AUTHENTICATION REQUIRED
//		  0x01 GSSAPI
//		  0x02 USERNAME/PASSWORD
//		  0x03 to 0x7F' IANA ASSIGNED
//		  0x80 to 0xFE' RESERVED FOR PRIVATE METHODS
//		  0xFF NO ACCEPTABLE METHODS
//	1. 服务端选择一个支持的加密模式响应客户端
//			 +----+--------+
//			|VER | METHOD |
//			+----+--------+
//			| 1  |   1    |
//			+----+--------+
// VER: 0x05
// METHOD: 选择一种密码模式
//   2. 客户端发起握手连接
//			+----+-----+-------+------+----------+----------+
//			|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//			+----+-----+-------+------+----------+----------+
//			| 1  |  1  | X'00' |  1   | Variable |    2     |
//			+----+-----+-------+------+----------+----------+
// VER: 0x05
// CMD:
//		CONNECT 0x01
//		BIND 	0x02
//		UDP 	0x03
// RSV: 0x00 保留
// ATYP: 用来指定DST.ADDR的类型及长度
//		IPV4:		  	0x01  4个字节
//		DOMAINNAME:		0x03  第一个字节指定DOMAINNAME的长度
//		IPV6 address: 	0x04  16个字节
// DST.ADDR:	可变长度
// DST.PORT:	端口
//	  2. 恢复客户端发起的握手连接
//			+----+-----+-------+------+----------+----------+
//			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//			+----+-----+-------+------+----------+----------+
//			| 1  |  1  | X'00' |  1   | Variable |    2     |
//			+----+-----+-------+------+----------+----------+
// VER: 0x05
// REP
//		0x00' succeeded
//		0x01' socket服务器故障
//		0x02' 不允许连接
//		0x03' 网络不可达
//		0x04' 主机无法访问
//		0x05' 连接拒绝
//		0x06' TTL过期
//		0x07' 命令不支持
//		0x08' 地址类型不支持
//		0x09' 之后的都未使用
// RSV   保留值 必须为0x00
// ATYP: 用来指定DST.ADDR的类型及长度
//		IPV4:		  	0x01  4个字节
//		DOMAINNAME:		0x03  第一个字节指定DOMAINNAME的长度
//		IPV6 address: 	0x04  16个字节

// BND.ADDR  服务器绑定的地址
// BND.PORT  服务器绑定的端口

// UDP请求
//			+----+------+------+----------+----------+----------+
//			|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//			+----+------+------+----------+----------+----------+
//			| 2  |  1   |  1   | Variable |    2     | Variable |
//			+----+------+------+----------+----------+----------+
// RSV 保留值 Ox0000
// FRAG udp分段序号
// ATYP
//		IPV4:		  	0x01  4个字节
//		DOMAINNAME:		0x03  第一个字节指定DOMAINNAME的长度
//		IPV6 address: 	0x04  16个字节
// DST.ADDR  目标地址
// DST.PORT  目标端口
// DATA		 用户数据

// 版本
const Version = 0x05

//命令
const (
	CMD_CONNECT = 0x01
	CMD_BIND    = 0x02
	CMD_UDP     = 0x03
)

// 连接状态
const (
	//		0x00' succeeded
	REP_0 = 0x00
	//		0x01' socket服务器故障
	REP_1 = 0x01
	//		0x02' 不允许连接
	REP_2 = 0x02
	//		0x03' 网络不可达
	REP_3 = 0x03
	//		0x04' 主机无法访问
	REP_4 = 0x04
	//		0x05' 连接拒绝
	REP_5 = 0x05
	//		0x06' TTL过期
	REP_6 = 0x06
	//		0x07' 命令不支持
	REP_7 = 0x07
	//		0x08' 地址类型不支持
	REP_8 = 0x08
	//		0x09' 之后的都未使用

)

// 保留位
const RSV = 0x00

// 目标地址类型
const (
	ATYP_IPV4       = 0x01
	ATYP_DOMAINNAME = 0x03
	ATYP_IPV6       = 0x04
)

type Socks5 struct {
	conn net.Conn
	bfr  *bufio.Reader
	atyp byte
	addr []byte
	port []byte
}

func NewSocks5(conn net.Conn) Socks5 {
	return Socks5{conn: conn, bfr: bufio.NewReader(conn)}
}

func (socks *Socks5) Valid() bool {
	firstByte, e := socks.bfr.ReadByte()
	if e == nil && firstByte == Version {
		return true
	}
	return false
}

func (socks *Socks5) GetAddr() (string, error) {
	firstByte, e := socks.bfr.ReadByte()
	if e != nil {
		return "", e
	}
	switch firstByte {
	case ATYP_IPV4:
    addrBytes:=make([]byte,4)
		socks.bfr.Read(addrBytes)
    socks.addr=addrBytes
		break
	case ATYP_DOMAINNAME:
		lenght, _ := socks.bfr.ReadByte()
		addrBytes:=make([]byte,lenght)
		socks.bfr.Read(addrBytes[:lenght])
		socks.addr=addrBytes
		break
	case ATYP_IPV6:
    addrBytes:=make([]byte,16)
		socks.bfr.Read(addrBytes)
    socks.addr=addrBytes
    break
	}
	portBytes:=make([]byte,2)
	socks.bfr.Read(portBytes)
	socks.port=portBytes
	addr := string(socks.addr)
	port := binary.BigEndian.Uint16(socks.port)
	return fmt.Sprintf("%s:%d", addr, port), nil
}

func (socks *Socks5) GetMethods() ([]byte, error) {
	firstByte, e := socks.bfr.ReadByte()

	if e == nil {
		bs := make([]byte, firstByte)
		_, e = socks.bfr.Read(bs)
		if e == nil {
			return bs[:], e
		}
	}
	return nil, e
}

func (socks *Socks5) ReplyAsk(method byte) {
	length, e := socks.conn.Write([]byte{
		Version,
		method,
	})
	log.Println(e)
	log.Println(length)
}

func (socks *Socks5) ValidConn() bool {
	if socks.Valid() {
		firstByte, e := socks.bfr.ReadByte()
		if e == nil {
			switch firstByte {
			case CMD_CONNECT:
				socks.bfr.ReadByte()
				return true
			}
		}
	}
	return false
}

func (socks *Socks5) ReplyConn(rep int) error {
	repl := []byte{
		Version,
		byte(rep),
		RSV,
		socks.atyp,
	}
	if socks.atyp==ATYP_DOMAINNAME{
    repl = append(repl, byte(len(socks.addr)))
  }
	repl = append(repl, socks.addr...)
	repl = append(repl, socks.port...)
	_, e := socks.conn.Write(repl)
	return e
}

func (socks *Socks5) Exchange(rc net.Conn) {
	go io.Copy(rc, socks.bfr)
	io.Copy(socks.conn, rc)
}

func (socks *Socks5) SetAddr(bytes []byte) {
	socks.addr = bytes
}

func (socks *Socks5) SetPort(bytes []byte) {
	socks.port = bytes
}

func (socks *Socks5) Ask() bool {
	ask := []byte{
		Version,
		1,
		0,
	}
	length, e := socks.conn.Write(ask)
	if e != nil || length != len(ask) {
		return false
	}
	return socks.validReplyAsk()
}

func (socks *Socks5) validReplyAsk() bool {
	b, e := socks.bfr.ReadByte()
	if e != nil {
		return false
	}
	socks.bfr.ReadByte()
	return b == Version
}

func (socks *Socks5) Conn(cmd int) bool {
	req := []byte{
		Version,
		byte(cmd),
		RSV,
		socks.atyp,

	}
  if socks.atyp==ATYP_DOMAINNAME{
    req = append(req, byte(len(socks.addr)))
  }
	req = append(req, socks.addr...)
	req = append(req, socks.port...)
	length, e := socks.conn.Write(req)
	if e != nil || length != len(req) {
		return false
	}
	return socks.validReplyConn()
}

func (socks *Socks5) validReplyConn() bool {
	if socks.Valid() {
    b, e := socks.bfr.ReadByte()
    io.ReadFull(socks.bfr,[]byte{})
		return e == nil && b == REP_0
	}
	return false
}

func (socks *Socks5) SetATYP(atyp int) {
	socks.atyp = byte(atyp)
}
