package dpi

import (
	"encoding/binary"
	"strings"
)

func ExtractSNI(payload []byte) (sni string) {
	defer func() {
		if r := recover(); r != nil {
			sni = ""
		}
	}()
	if len(payload) < 5 || payload[0] != 0x16 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return ""
	}
	record := payload[5 : 5+recordLen]
	if len(record) < 1 || record[0] != 0x01 {
		return ""
	}
	if len(record) < 4 {
		return ""
	}
	handshakeLen := int(binary.BigEndian.Uint32(append([]byte{0}, record[1:4]...)))
	if len(record) < 4+handshakeLen {
		return ""
	}
	handshake := record[4 : 4+handshakeLen]

	pos := 2

	if pos+32 > len(handshake) {
		return ""
	}
	pos += 32

	if pos >= len(handshake) {
		return ""
	}
	sessionIDLen := int(handshake[pos])
	pos += 1
	if pos+sessionIDLen > len(handshake) {
		return ""
	}
	pos += sessionIDLen

	if pos+2 > len(handshake) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2
	if pos+cipherSuitesLen > len(handshake) {
		return ""
	}
	pos += cipherSuitesLen

	if pos >= len(handshake) {
		return ""
	}
	compressionLen := int(handshake[pos])
	pos += 1
	if pos+compressionLen > len(handshake) {
		return ""
	}
	pos += compressionLen

	if pos+2 > len(handshake) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2
	if pos+extensionsLen > len(handshake) {
		return ""
	}
	extensions := handshake[pos : pos+extensionsLen]

	for extPos := 0; extPos+4 <= len(extensions); {
		extType := binary.BigEndian.Uint16(extensions[extPos : extPos+2])
		extLen := int(binary.BigEndian.Uint16(extensions[extPos+2 : extPos+4]))
		if extType == 0x0000 {
			if extPos+4+extLen > len(extensions) {
				return ""
			}
			sniData := extensions[extPos+4 : extPos+4+extLen]
			if len(sniData) < 5 {
				return ""
			}
			sniListLen := int(binary.BigEndian.Uint16(sniData[0:2]))
			if len(sniData) < 2+sniListLen {
				return ""
			}
			sniItem := sniData[2 : 2+sniListLen]
			if len(sniItem) < 3 {
				return ""
			}
			if sniItem[0] != 0x00 {
				return ""
			}
			hostLen := int(binary.BigEndian.Uint16(sniItem[1:3]))
			if 3+hostLen > len(sniItem) {
				return ""
			}
			return strings.ToLower(string(sniItem[3 : 3+hostLen]))
		}
		extPos += 4 + extLen
	}
	return ""
}

func ExtractHTTPHost(payload []byte) (host string) {
	defer func() {
		if r := recover(); r != nil {
			host = ""
		}
	}()
	end := len(payload)
	if end > 4096 {
		end = 4096
	}
	data := payload[:end]

	headerEnd := indexBytes(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return ""
	}
	head := data[:headerEnd]
	lines := splitBytes(head, []byte("\r\n"))
	if len(lines) == 0 {
		return ""
	}

	requestLine := string(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return ""
	}
	uri := parts[1]

	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		hostStart := strings.Index(uri, "://") + 3
		hostRemainder := uri[hostStart:]
		hostEnd := strings.IndexByte(hostRemainder, '/')
		var host string
		if hostEnd >= 0 {
			host = hostRemainder[:hostEnd]
		} else {
			host = hostRemainder
		}
		if colonIdx := strings.LastIndexByte(host, ':'); colonIdx >= 0 {
			host = host[:colonIdx]
		}
		return strings.ToLower(host)
	}

	for _, line := range lines[1:] {
		if len(line) < 6 {
			continue
		}
		lower := strings.ToLower(string(line))
		if strings.HasPrefix(lower, "host:") {
			hostVal := strings.TrimSpace(string(line[5:]))
			if colonIdx := strings.LastIndexByte(hostVal, ':'); colonIdx >= 0 {
				hostVal = hostVal[:colonIdx]
			}
			return strings.ToLower(hostVal)
		}
	}
	return ""
}

func indexBytes(data, sub []byte) int {
	for i := 0; i <= len(data)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if data[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func splitBytes(data, sep []byte) [][]byte {
	var result [][]byte
	for {
		idx := indexBytes(data, sep)
		if idx < 0 {
			result = append(result, data)
			break
		}
		result = append(result, data[:idx])
		data = data[idx+len(sep):]
	}
	return result
}
