package main

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
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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

// RFC 8489 Section 2: "The Binding method can be used to determine the particular binding a NAT has allocated to a STUN client"
func (c *STUNClient) SendBindingRequest(serverAddr string, changeIP, changePort bool) (*net.UDPAddr, error) {
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
	
	// 送信
	_, err = c.conn.WriteToUDP(data, addr)
	if err != nil {
		return nil, err
	}
	
	// レスポンス受信
	// RFC 8489 Section 6.3.1.1: "When forming the success response, the server adds an XOR-MAPPED-ADDRESS attribute"
	// CHANGE-REQUESTの場合は異なるサーバーからの応答を待つため、タイムアウトを延長
	timeout := 3 * time.Second
	if changeIP || changePort {
		timeout = 5 * time.Second
	}
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	n, _, err := c.conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	// レスポンス解析
	response, err := c.decodeMessage(buffer[:n])
	if err != nil {
		return nil, err
	}

	// エラーレスポンスのチェック
	if response.MessageType == BindingErrorResponse {
		code, reason := extractErrorCode(response)
		return nil, fmt.Errorf("STUN error response: code=%d, reason=%s", code, reason)
	}
	
	// RFC 8489 Section 14.2: "The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS attribute, except that the reflexive transport address is obfuscated."
	// RFC 8489 Section 14.1: "The MAPPED-ADDRESS attribute indicates a reflexive transport address of the client."
	// XOR-MAPPED-ADDRESSまたはMAPPED-ADDRESSを探す
	for _, attr := range response.Attributes {
		if attr.Type == XorMappedAddress {
			return c.parseAddress(attr.Value, true, response.TransactionID)
		}
		if attr.Type == MappedAddress {
			return c.parseAddress(attr.Value, false, response.TransactionID)
		}
	}
	
	return nil, fmt.Errorf("mapped address not found in response")
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

	// MessageLengthを読み取るが、構造体には保存しない（検証のみに使用）
	// RFC 8489 Section 5: "The message length MUST contain the size, in bytes, of the message not including the 20-byte STUN header."
	messageLength := binary.BigEndian.Uint16(data[2:4])
	_ = messageLength // 現在は未使用だが、将来的な検証に使用可能

	copy(msg.TransactionID[:], data[8:20])
	
	// アトリビュート解析
	// RFC 8489 Section 14: "After the STUN header are zero or more attributes."
	offset := 20
	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		// RFC 8489 Section 14: "Each attribute is TLV (Type-Length-Value) encoded"
		attrType := STUNAttributeType(binary.BigEndian.Uint16(data[offset:offset+2]))
		attrLength := binary.BigEndian.Uint16(data[offset+2:offset+4])
		
		if offset+4+int(attrLength) > len(data) {
			break
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
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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

// isChangeRequestUnsupportedError はエラーがCHANGE-REQUEST非対応を示すかチェック
//
// RFC 8489 Section 14.8: エラーコード420 "Unknown Attribute"
// "The server did not understand a comprehension-required attribute in the request."
//
// CHANGE-REQUEST属性（RFC 3489）はRFC 8489で削除されたため、多くの最新の
// STUNサーバーはこの属性を理解せず、エラーコード420を返します。
// この場合、フィルタリング判定は不可能と判断します。
func isChangeRequestUnsupportedError(msg *STUNMessage) bool {
	code, _ := extractErrorCode(msg)
	// エラーコード 420: Unknown Attribute
	// CHANGE-REQUEST属性が未サポートの場合に返される
	return code == 420
}

// GetAlternateAddress はSTUNサーバーからOTHER-ADDRESS (代替アドレス) を取得します
//
// RFC 5780 Section 7.2: "The OTHER-ADDRESS attribute is used in Binding Responses.
//                        It informs the client of the source IP address and port that
//                        would be used if the client requested the 'change IP' and
//                        'change port' behavior."
//
// この代替アドレスは、CHANGE-REQUESTテスト（Test II, III）で使用され、
// NATフィルタリング動作の判定に必要です。
//
// 注意: 多くのSTUNサーバーはOTHER-ADDRESSをサポートしていません。
//       その場合、CHANGED-ADDRESS (RFC 3489) へのフォールバックを試みます。
func (c *STUNClient) GetAlternateAddress(serverAddr string) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}

	// トランザクションID生成
	var txID [12]byte
	rand.Read(txID[:])

	msg := STUNMessage{
		MessageType:   BindingRequest,
		TransactionID: txID,
	}

	// メッセージをバイト列に変換
	data := c.encodeMessage(msg)

	// 送信
	_, err = c.conn.WriteToUDP(data, addr)
	if err != nil {
		return nil, err
	}

	// レスポンス受信
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, _, err := c.conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	// レスポンス解析
	response, err := c.decodeMessage(buffer[:n])
	if err != nil {
		return nil, err
	}

	// OTHER-ADDRESSまたはCHANGED-ADDRESSを探す
	for _, attr := range response.Attributes {
		if attr.Type == OtherAddress || attr.Type == ChangedAddress {
			return c.parseAddress(attr.Value, false, response.TransactionID)
		}
	}

	return nil, fmt.Errorf("OTHER-ADDRESS not found in response")
}