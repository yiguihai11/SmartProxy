package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

func Handshake(rw io.ReadWriter, serverUser, serverPass string) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(rw, buf); err != nil {
		return fmt.Errorf("failed to read version/methods: %w", err)
	}
	ver, nmethods := buf[0], buf[1]
	if ver != Version5 {
		return errors.New("invalid SOCKS version")
	}
	if nmethods == 0 {
		return errors.New("no authentication methods offered")
	}

	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(rw, methods); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	hasAuth := serverUser != "" && serverPass != ""
	noAuthFound := false
	userPassFound := false
	for _, m := range methods {
		if m == NoAuth {
			noAuthFound = true
		}
		if m == UserPass {
			userPassFound = true
		}
	}

	if hasAuth {
		if !userPassFound {
			if _, err := rw.Write([]byte{Version5, NoAccept}); err != nil {
				return err
			}
			return errors.New("authentication required, client did not offer UserPass method")
		}
	} else if noAuthFound {
		if _, err := rw.Write([]byte{Version5, NoAuth}); err != nil {
			return err
		}
		return nil
	}

	if userPassFound && hasAuth {
		if _, err := rw.Write([]byte{Version5, UserPass}); err != nil {
			return err
		}

		authBuf := make([]byte, 2)
		if _, err := io.ReadFull(rw, authBuf); err != nil {
			return fmt.Errorf("failed to read auth version/ulen: %w", err)
		}
		if authBuf[0] != AuthVer {
			return errors.New("invalid auth version")
		}
		ulen := int(authBuf[1])
		username := make([]byte, ulen)
		if _, err := io.ReadFull(rw, username); err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}
		plenByte := make([]byte, 1)
		if _, err := io.ReadFull(rw, plenByte); err != nil {
			return fmt.Errorf("failed to read password length: %w", err)
		}
		plen := int(plenByte[0])
		password := make([]byte, plen)
		if _, err := io.ReadFull(rw, password); err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}

		if string(username) == serverUser && string(password) == serverPass {
			if _, err := rw.Write([]byte{AuthVer, AuthPassed}); err != nil {
				return err
			}
			return nil
		}
		if _, err := rw.Write([]byte{AuthVer, AuthFailed}); err != nil {
			return err
		}
		return errors.New("authentication failed")
	}

	if _, err := rw.Write([]byte{Version5, NoAccept}); err != nil {
		return err
	}
	return errors.New("no acceptable authentication method")
}

type ProtocolError struct {
	Reply Reply
	Msg   string
}

func (e *ProtocolError) Error() string { return e.Msg }

type Request struct {
	Command Command
	Host    string
	Port    int
}

func ReceiveRequest(r io.Reader) (*Request, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("failed to read request header: %w", err)
	}
	ver, cmd, rsv, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != Version5 || rsv != RSV {
		return nil, &ProtocolError{Reply: ReplyGeneralFailure, Msg: "invalid request header"}
	}

	var host string
	switch atyp {
	case byte(AddrIPv4):
		raw := make([]byte, 4)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, err
		}
		host = net.IP(raw).String()
	case byte(AddrIPv6):
		raw := make([]byte, 16)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, err
		}
		host = net.IP(raw).String()
	case byte(AddrDomain):
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(r, lenByte); err != nil {
			return nil, err
		}
		domainLen := lenByte[0]
		if domainLen == 0 {
			return nil, errors.New("empty domain name in request")
		}
		raw := make([]byte, domainLen)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, err
		}
		host = string(raw)
	default:
		return nil, &ProtocolError{Reply: ReplyAddrNotSupport, Msg: fmt.Sprintf("unsupported address type: %d", atyp)}
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	return &Request{Command: Command(cmd), Host: host, Port: port}, nil
}

func SendReply(w io.Writer, reply Reply, bindHost string, bindPort int) error {

	if bindHost == "" {
		if bindPort == 0 {
			bindHost = "0.0.0.0"
		} else {
			bindHost = "0.0.0.0"
		}
	}

	ip := net.ParseIP(bindHost)
	var atyp byte
	var addr []byte
	if ip == nil {
		atyp = byte(AddrDomain)
		domain := []byte(bindHost)
		if len(domain) == 0 {
			return fmt.Errorf("invalid SOCKS5 reply: empty bind host")
		}
		addr = append([]byte{byte(len(domain))}, domain...)
	} else if ip.To4() != nil {
		atyp = byte(AddrIPv4)
		addr = ip.To4()
	} else {
		atyp = byte(AddrIPv6)
		addr = ip.To16()
	}

	header := []byte{Version5, byte(reply), RSV, atyp}
	header = append(header, addr...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(bindPort))
	header = append(header, portBytes...)

	_, err := w.Write(header)
	return err
}
