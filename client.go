package natchecker

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// STUNメッセージタイプ
type STUNMessageType uint16

const (
	// BindingRequest (0x0001) - STUNバインディングリクエスト
	// RFC 8489 Section 6: "The Binding method can be used to determine the
	//                      particular binding a NAT has allocated to a STUN client."
	// メッセージタイプ構造: Method=0x001 (Binding), Class=0b00 (Request)
	BindingRequest STUNMessageType = 0x0001

	// BindingResponse (0x0101) - STUNバインディング成功レスポンス
	// RFC 8489 Section 6: "When the Binding method is used in a success response,
	//                      the server adds an XOR-MAPPED-ADDRESS attribute."
	// メッセージタイプ構造: Method=0x001 (Binding), Class=0b10 (Success Response)
	BindingResponse STUNMessageType = 0x0101

	// BindingErrorResponse (0x0111) - STUNバインディングエラーレスポンス
	// RFC 8489 Section 6: "For an error response, the server MUST add an ERROR-CODE
	//                      attribute containing the error code specified."
	// メッセージタイプ構造: Method=0x001 (Binding), Class=0b11 (Error Response)
	BindingErrorResponse STUNMessageType = 0x0111
)

// STUNアトリビュートタイプ
type STUNAttributeType uint16

const (
	// MAPPED-ADDRESS 属性 (Type 0x0001)
	// RFC 8489 Section 14.1: "The MAPPED-ADDRESS attribute indicates a reflexive
	//                         transport address of the client"
	MappedAddress STUNAttributeType = 0x0001

	// XOR-MAPPED-ADDRESS 属性 (Type 0x0020)
	// RFC 8489 Section 14.2: "The XOR-MAPPED-ADDRESS attribute is identical to the
	//                         MAPPED-ADDRESS attribute, except that the reflexive
	//                         transport address is obfuscated through the XOR function"
	XorMappedAddress STUNAttributeType = 0x0020

	// CHANGE-REQUEST 属性 (Type 0x0003) - RFC 3489のみ
	// RFC 3489 Section 11.2.4: "The CHANGE-REQUEST attribute is used by the client to
	//                           request that the server use a different address and/or
	//                           port when sending the response"
	// 注意: この属性はRFC 8489で削除されましたが、RFC 5780のNAT検出に必要です
	ChangeRequest STUNAttributeType = 0x0003

	// CHANGED-ADDRESS 属性 (Type 0x0005) - RFC 3489のみ
	// RFC 3489: サーバーの代替IP:Portを示す（OTHER-ADDRESSの前身）
	ChangedAddress STUNAttributeType = 0x0005

	// OTHER-ADDRESS 属性 (Type 0x802C)
	// RFC 5780 Section 7.2: "The OTHER-ADDRESS attribute is used in Binding Responses.
	//                        It informs the client of the source IP address and port
	//                        that would be used if the client requested the 'change IP'
	//                        and 'change port' behavior"
	// 注意: RFC 3489のCHANGED-ADDRESSと同じ属性番号を使用
	OtherAddress STUNAttributeType = 0x802C

	// ERROR-CODE 属性 (Type 0x0009)
	// RFC 8489 Section 14.8: "The ERROR-CODE attribute is used in error response messages.
	//                         It contains a numeric error code value in the range of
	//                         300 to 699 plus a textual reason phrase"
	ErrorCode STUNAttributeType = 0x0009
)

// STUN Magic Cookie
// RFC 8489 Section 5: "The magic cookie field MUST contain the fixed value 0x2112A442 in network byte order."
const STUNMagicCookie uint32 = 0x2112A442

// バイト列で使いたい時もあるので、あらかじめ用意しておく
var STUNMagicCookieBytes = []byte{0x21, 0x12, 0xA4, 0x42}

// STUN リクエストメッセージ構造体
// RFC 8489 Section 5: "STUN Message Structure"
//
// STUN Message Header (20 bytes):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|0 0|     STUN Message Type     |         Message Length        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         Magic Cookie                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	|                     Transaction ID (96 bits)                  |
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type STUNMessage struct {
	MessageType   STUNMessageType
	TransactionID [12]byte
	Attributes    []STUNAttribute
}

// RFC 8489 Section 14: "STUN Attributes" の 1 要素を表す
//
// 属性フォーマット:
// ```text
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Type                  |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Value (variable)                ....
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// ```
type STUNAttribute struct {
	Type   STUNAttributeType
	Length uint16
	Value  []byte
}

// STUNError はサーバーからの STUN エラーレスポンス (RFC 8489 Section 14.8) を表します。
//
// タイムアウトや ICMP unreachable などのネットワークエラーと区別するための
// sentinel エラー型で、errors.As で判別できます。
// 例: エラーコード 420 (Unknown Attribute) は CHANGE-REQUEST 非対応サーバーが返す。
type STUNError struct {
	Code   int
	Reason string
}

func (e *STUNError) Error() string {
	return fmt.Sprintf("STUN error response: code=%d, reason=%s", e.Code, e.Reason)
}

// STUNクライアント
type STUNClient struct {
	conn *net.UDPConn
}

func NewSTUNClient() (*STUNClient, error) {
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	return &STUNClient{conn: conn}, nil
}

func (c *STUNClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// LocalAddr は server へ送信する際に使われるローカル IP と、クライアントが
// バインドしているポートの組を返します。
//
// conn は ":0"（全インターフェース・任意ポート）にバインドされているため
// conn.LocalAddr() だけでは送信元 IP が分からない。実際の送信元 IP は
// 宛先へのルーティングで決まるので、プローブ用の接続で解決する。
func (c *STUNClient) LocalAddr(server *net.UDPAddr) (*net.UDPAddr, error) {
	probe, err := net.DialUDP("udp", nil, server)
	if err != nil {
		return nil, err
	}
	defer probe.Close()

	return &net.UDPAddr{
		IP:   probe.LocalAddr().(*net.UDPAddr).IP,
		Port: c.conn.LocalAddr().(*net.UDPAddr).Port,
	}, nil
}

// BindingResult は Binding トランザクション 1 往復で得られる情報
type BindingResult struct {
	// MappedAddress はクライアントの外部アドレス
	// (XOR-MAPPED-ADDRESS または MAPPED-ADDRESS)
	MappedAddress *net.UDPAddr
	// OtherAddress はサーバーの代替アドレス
	// (OTHER-ADDRESS または CHANGED-ADDRESS)。レスポンスに含まれなければ nil
	OtherAddress *net.UDPAddr
	// ResponseFrom はレスポンスの送信元アドレス
	ResponseFrom *net.UDPAddr
}

// RFC 8489 Section 2: "The Binding method can be used to determine the particular binding a NAT has allocated to a STUN client"
func (c *STUNClient) SendBindingRequest(serverAddr string, changeIP, changePort bool) (*BindingResult, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}

	// トランザクションID生成
	// RFC 8489 Section 5: "The transaction ID is a 96-bit identifier, used to uniquely identify STUN transactions."
	// RFC 8489 Section 5: "The transaction ID MUST be uniformly and randomly chosen from the interval 0 .. 2**96-1, and MUST be cryptographically random."
	var txID [12]byte
	rand.Read(txID[:])

	msg := STUNMessage{
		MessageType:   BindingRequest,
		TransactionID: txID,
	}

	// Change Requestアトリビュート追加
	// RFC 3489 Section 11.2.4: CHANGE-REQUEST Attribute
	// 注意: この属性はRFC 3489で定義され、RFC 8489では削除されています。
	// RFC 5780のNAT動作検出に使用されますが、多くのSTUNサーバーでは実装されていません。
	//
	// Format (RFC 3489):
	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// A (bit 2): Change IP flag - サーバーに異なるIPアドレスからの応答を要求
	// B (bit 1): Change Port flag - サーバーに異なるポートからの応答を要求
	if changeIP || changePort {
		changeValue := uint32(0)
		if changeIP {
			changeValue |= 0x04 // Change IP flag (bit 2)
		}
		if changePort {
			changeValue |= 0x02 // Change Port flag (bit 1)
		}

		valueBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(valueBytes, changeValue)

		msg.Attributes = append(msg.Attributes, STUNAttribute{
			Type:   ChangeRequest,
			Length: 4,
			Value:  valueBytes,
		})
	}

	// メッセージをバイト列に変換
	data := c.encodeMessage(msg)

	// 送信・レスポンス受信（応答がなければ再送）
	// RFC 8489 Section 6.3.1.1: "When forming the success response, the server adds an XOR-MAPPED-ADDRESS attribute"
	response, from, err := c.roundTrip(addr, data, txID)
	if err != nil {
		return nil, err
	}

	// エラーレスポンスのチェック
	if response.MessageType == BindingErrorResponse {
		code, reason := extractErrorCode(response)
		return nil, &STUNError{Code: code, Reason: reason}
	}

	result := &BindingResult{ResponseFrom: from}

	// RFC 8489 Section 14.2: "The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS attribute, except that the reflexive transport address is obfuscated."
	// RFC 8489 Section 14.1: "The MAPPED-ADDRESS attribute indicates a reflexive transport address of the client."
	// RFC 5780 Section 7.2: OTHER-ADDRESS も同じ Binding Response に含まれるため、
	// 1 往復でまとめて取得する
	var mappedAddress, xorMappedAddress *net.UDPAddr
	for _, attr := range response.Attributes {
		switch attr.Type {
		case XorMappedAddress:
			xorMappedAddress, err = c.parseAddress(attr.Value, true, response.TransactionID)
			if err != nil {
				return nil, err
			}
		case MappedAddress:
			mappedAddress, err = c.parseAddress(attr.Value, false, response.TransactionID)
			if err != nil {
				return nil, err
			}
		case OtherAddress, ChangedAddress:
			// 代替アドレスが解析できなくても Binding 自体は成立しているので
			// エラーにはせず nil のままにする
			if otherAddr, parseErr := c.parseAddress(attr.Value, false, response.TransactionID); parseErr == nil {
				result.OtherAddress = otherAddr
			}
		}
	}

	// XOR-MAPPED-ADDRESS を優先する
	result.MappedAddress = xorMappedAddress
	if result.MappedAddress == nil {
		result.MappedAddress = mappedAddress
	}
	if result.MappedAddress == nil {
		return nil, fmt.Errorf("mapped address not found in response")
	}

	return result, nil
}

// RFC 8489 Section 6.2.1 の再送パラメータ
// RTO 500ms から指数バックオフで再送する。RFC のデフォルト (Rc=7) では
// タイムアウト確定までに約 40 秒かかるため、NAT 判定用途では送信回数を
// 4 回に抑えている（タイムアウト確定まで約 7.5 秒）。
const (
	stunInitialRTO    = 500 * time.Millisecond
	stunTransmitCount = 4
)

// roundTrip は STUN リクエストを送信し、Transaction ID の一致するレスポンスと
// その送信元アドレスを返します。応答がなければ RTO を倍にしながら再送します。
//
// RFC 8489 Section 6.2.1: "RTO SHOULD be greater than 500 ms" /
// "the client retransmits the request, doubling the RTO"
// UDP パケットが 1 つ落ちただけでタイムアウト（＝フィルタリング判定では
// 「フィルタされた」と解釈される）になるのを防ぐため、再送してから結論を出す。
func (c *STUNClient) roundTrip(server *net.UDPAddr, request []byte, txID [12]byte) (*STUNMessage, *net.UDPAddr, error) {
	rto := stunInitialRTO
	var lastErr error

	for attempt := 0; attempt < stunTransmitCount; attempt++ {
		if _, err := c.conn.WriteToUDP(request, server); err != nil {
			return nil, nil, err
		}

		msg, from, err := c.readResponse(time.Now().Add(rto), txID)
		if err == nil {
			return msg, from, nil
		}

		// タイムアウト以外のエラーは再送しても回復しないため即座に返す
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			return nil, nil, err
		}

		lastErr = err
		rto *= 2
	}

	return nil, nil, lastErr
}

// readResponse は deadline まで受信を試み、Transaction ID が一致する STUN
// レスポンスとその送信元アドレスを返します。
//
// RFC 8489 Section 6.3.1: "the transaction ID that matches an existing STUN
// transaction" — 送信した txID と一致しない応答は別トランザクションの
// 遅延応答や無関係な UDP パケットなので、読み捨てて再受信します。
// これにより、タイムアウトした Test II の遅延応答がソケットバッファに残って
// Test III の応答として誤読されることを防ぎます。
func (c *STUNClient) readResponse(deadline time.Time, txID [12]byte) (*STUNMessage, *net.UDPAddr, error) {
	buffer := make([]byte, 1500)
	for {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return nil, nil, err
		}

		n, from, err := c.conn.ReadFromUDP(buffer)
		if err != nil {
			return nil, nil, err
		}

		msg, err := c.decodeMessage(buffer[:n])
		if err != nil {
			// STUN メッセージとして解釈できないパケットは無視して再受信
			continue
		}

		if msg.TransactionID != txID {
			// 別トランザクションの応答は無視して再受信
			continue
		}

		return msg, from, nil
	}
}

// RFC 8489 Section 5: "All STUN messages comprise a 20-byte header followed by zero or more attributes"
func (c *STUNClient) encodeMessage(msg STUNMessage) []byte {
	// アトリビュート部分の長さ計算
	attrLen := 0
	for _, attr := range msg.Attributes {
		attrLen += 4 + int(attr.Length) // type(2) + length(2) + value
		// RFC 8489 Section 14: "Attributes are TLV (Type-Length-Value) encoded."
		// RFC 8489 Section 14: "Attributes MUST be padded to a multiple of 4 bytes."
		if attr.Length%4 != 0 {
			attrLen += 4 - int(attr.Length%4)
		}
	}

	data := make([]byte, 20+attrLen) // ヘッダー20バイト + アトリビュート

	// ヘッダー
	// RFC 8489 Section 5: "The message type field is 2 bytes"
	binary.BigEndian.PutUint16(data[0:2], uint16(msg.MessageType))
	// RFC 8489 Section 5: "The message length MUST contain the size of the message in bytes, not including the 20-byte STUN header."
	binary.BigEndian.PutUint16(data[2:4], uint16(attrLen))
	// RFC 8489 Section 5: "The magic cookie field MUST contain the fixed value 0x2112A442"
	binary.BigEndian.PutUint32(data[4:8], STUNMagicCookie)
	// RFC 8489 Section 5: "The transaction ID is a 96-bit (12-byte) identifier"
	copy(data[8:20], msg.TransactionID[:])

	// アトリビュート
	// RFC 8489 Section 14: "After the STUN header are zero or more attributes."
	offset := 20
	for _, attr := range msg.Attributes {
		// RFC 8489 Section 14: "Each attribute is TLV (Type-Length-Value) encoded"
		binary.BigEndian.PutUint16(data[offset:offset+2], uint16(attr.Type))
		binary.BigEndian.PutUint16(data[offset+2:offset+4], attr.Length)
		copy(data[offset+4:offset+4+int(attr.Length)], attr.Value)
		offset += 4 + int(attr.Length)

		// RFC 8489 Section 14: "Attributes are padded to a 4-byte boundary; the padding bits are ignored"
		if attr.Length%4 != 0 {
			offset += 4 - int(attr.Length%4)
		}
	}

	return data
}

// RFC 8489 Section 5: "All STUN messages comprise a 20-byte header followed by zero or more attributes"
func (c *STUNClient) decodeMessage(data []byte) (*STUNMessage, error) {
	// RFC 8489 Section 5: "All STUN messages comprise a 20-byte header"
	if len(data) < 20 {
		return nil, fmt.Errorf("message too short")
	}

	msg := &STUNMessage{
		MessageType: STUNMessageType(binary.BigEndian.Uint16(data[0:2])),
	}

	// RFC 8489 Section 5: "The magic cookie field MUST contain the fixed value 0x2112A442"
	// Magic Cookie が一致しないパケットは STUN メッセージではないため弾く
	if binary.BigEndian.Uint32(data[4:8]) != STUNMagicCookie {
		return nil, fmt.Errorf("invalid magic cookie: 0x%08x", binary.BigEndian.Uint32(data[4:8]))
	}

	// RFC 8489 Section 5: "The message length MUST contain the size, in bytes, of the message not including the 20-byte STUN header."
	messageLength := int(binary.BigEndian.Uint16(data[2:4]))
	if 20+messageLength > len(data) {
		return nil, fmt.Errorf("message length %d exceeds packet size %d", messageLength, len(data))
	}
	// 属性のパースは Message Length が示す範囲を上限とする
	// （UDP パケット末尾に余分なデータがあっても無視する）
	end := 20 + messageLength

	copy(msg.TransactionID[:], data[8:20])

	// アトリビュート解析
	// RFC 8489 Section 14: "After the STUN header are zero or more attributes."
	offset := 20
	for offset < end {
		if offset+4 > end {
			return nil, fmt.Errorf("truncated attribute header at offset %d", offset)
		}

		// RFC 8489 Section 14: "Each attribute is TLV (Type-Length-Value) encoded"
		attrType := STUNAttributeType(binary.BigEndian.Uint16(data[offset : offset+2]))
		attrLength := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		if offset+4+int(attrLength) > end {
			return nil, fmt.Errorf("truncated attribute value at offset %d", offset)
		}

		attr := STUNAttribute{
			Type:   attrType,
			Length: attrLength,
			Value:  make([]byte, attrLength),
		}
		copy(attr.Value, data[offset+4:offset+4+int(attrLength)])

		msg.Attributes = append(msg.Attributes, attr)

		offset += 4 + int(attrLength)
		// RFC 8489 Section 14: "Attributes are padded to a 4-byte boundary"
		// パディングをスキップ
		if attrLength%4 != 0 {
			offset += 4 - int(attrLength%4)
		}
	}

	return msg, nil
}

// RFC 8489 Section 14.1 (MAPPED-ADDRESS) と Section 14.2 (XOR-MAPPED-ADDRESS) のアドレス解析
// MAPPED-ADDRESS と XOR-MAPPED-ADDRESS は同じ形式だが、XOR-MAPPED-ADDRESS は Magic Cookie と Transaction ID で XOR される
//
// MAPPED-ADDRESS format (RFC 8489 Section 14.1):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|0 0 0 0 0 0 0 0|    Family     |           Port                |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	|                 Address (32 bits or 128 bits)                 |
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// XOR-MAPPED-ADDRESS format (RFC 8489 Section 14.2):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|0 0 0 0 0 0 0 0|    Family     |         X-Port                |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                X-Address (Variable)
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (c *STUNClient) parseAddress(data []byte, isXor bool, txID [12]byte) (*net.UDPAddr, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("address data too short: %d bytes", len(data))
	}

	// RFC 8489 Section 14.1: "The address family can take on the following values: 0x01 (IPv4), 0x02 (IPv6)"
	// STUNアドレス形式: 1バイト予約 + 1バイトファミリー + 2バイトポート + IPアドレス
	family := data[1] // 2バイト目がファミリー
	port := binary.BigEndian.Uint16(data[2:4])

	var ip net.IP

	switch family {
	case 0x01: // IPv4
		// RFC 8489 Section 14.1: "If the address family is IPv4, the address MUST be 32 bits (4 bytes)"
		if len(data) < 8 {
			return nil, fmt.Errorf("IPv4 address data too short: %d bytes", len(data))
		}
		ip = make(net.IP, 4)
		copy(ip, data[4:8])

		if isXor {
			// RFC 8489 Section 14.2: "X-Port is computed by XOR'ing the mapped port with the most significant 16 bits of the magic cookie"
			// RFC 8489 Section 14.2: "X-Address is computed by XOR'ing the mapped IP address with the magic cookie"
			port ^= 0x2112 // 最上位16ビット of Magic Cookie
			for i := 0; i < 4; i++ {
				ip[i] ^= STUNMagicCookieBytes[i]
			}
		}

	case 0x02: // IPv6
		// RFC 8489 Section 14.1: "If the address family is IPv6, the address MUST be 128 bits (16 bytes)"
		if len(data) < 20 {
			return nil, fmt.Errorf("IPv6 address data too short: %d bytes", len(data))
		}
		ip = make(net.IP, 16)
		copy(ip, data[4:20])

		if isXor {
			// RFC 8489 Section 14.2: "X-Port is computed by XOR'ing the mapped port with the most significant 16 bits of the magic cookie"
			// RFC 8489 Section 14.2: "If the IP address family is IPv6, X-Address is computed by XOR'ing the mapped IP address with the concatenation of the magic cookie and the 96-bit transaction ID"
			port ^= 0x2112 // 最上位16ビット of Magic Cookie
			xorKey := make([]byte, 16)
			copy(xorKey[0:4], STUNMagicCookieBytes)
			copy(xorKey[4:16], txID[:])

			for i := 0; i < 16; i++ {
				ip[i] ^= xorKey[i]
			}
		}

	default:
		// 不明なファミリーの場合、デバッグ情報を含めてエラーを返す
		return nil, fmt.Errorf("unsupported address family: %d (0x%02x), data: %x", family, family, data)
	}

	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// extractErrorCode はSTUNエラーレスポンスからエラーコードを取得します
// RFC 8489 Section 14.8: ERROR-CODE Attribute (Type 0x0009)
//
// "The ERROR-CODE attribute is used in error response messages."
// "The error code is a numeric value in the range 300-699."
//
// Format:
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Reserved, should be 0         |Class|     Number    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Reason Phrase (variable)                                ..
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Class: 3ビット（エラーコードの百の位: 3-6）
// Number: 8ビット（エラーコードの十と一の位: 0-99）
// Error Code = Class * 100 + Number（例: Class=4, Number=20 → 420）
func extractErrorCode(msg *STUNMessage) (int, string) {
	for _, attr := range msg.Attributes {
		if attr.Type == ErrorCode && len(attr.Value) >= 4 {
			// RFC 8489: "The error code value is a number in the range 300 to 699"
			// エラーコード = Class * 100 + Number
			class := int(attr.Value[2] & 0x07) // バイト2の下位3ビット
			number := int(attr.Value[3])       // バイト3の全8ビット
			errorCode := class*100 + number

			// Reason Phrase（オプション、UTF-8エンコード）
			reason := ""
			if len(attr.Value) > 4 {
				reason = string(attr.Value[4:])
			}

			return errorCode, reason
		}
	}
	return 0, ""
}
