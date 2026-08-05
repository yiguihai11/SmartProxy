package socks5

const (
	Version5   = 0x05
	NoAuth     = 0x00
	UserPass   = 0x02
	NoAccept   = 0xFF
	AuthVer    = 0x01
	AuthPassed = 0x00
	AuthFailed = 0x01
	RSV        = 0x00
)

type Command byte

const (
	CommandConnect      Command = 0x01
	CommandBind         Command = 0x02
	CommandUDPAssociate Command = 0x03
)

type AddressType byte

const (
	AddrIPv4   AddressType = 0x01
	AddrDomain AddressType = 0x03
	AddrIPv6   AddressType = 0x04
)

type Reply byte

const (
	ReplySuccess         Reply = 0x00
	ReplyGeneralFailure  Reply = 0x01
	ReplyNotAllowed      Reply = 0x02
	ReplyNetUnreachable  Reply = 0x03
	ReplyHostUnreachable Reply = 0x04
	ReplyConnRefused     Reply = 0x05
	ReplyTTLExpired      Reply = 0x06
	ReplyCmdNotSupported Reply = 0x07
	ReplyAddrNotSupport  Reply = 0x08
)

func (c Command) String() string {
	switch c {
	case CommandConnect:
		return "CONNECT"
	case CommandBind:
		return "BIND"
	case CommandUDPAssociate:
		return "UDP_ASSOCIATE"
	default:
		return "UNKNOWN"
	}
}
