package natchecker

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSTUNClientCreation(t *testing.T) {
	client, err := NewSTUNClient()
	require.NoError(t, err, "NewSTUNClient() should not fail")
	defer client.Close()

	assert.NotNil(t, client.conn, "STUNClient connection should not be nil")
}

func TestSTUNMessageEncoding(t *testing.T) {
	client, err := NewSTUNClient()
	require.NoError(t, err, "NewSTUNClient() should not fail")
	defer client.Close()

	msg := STUNMessage{
		MessageType:   BindingRequest,
		TransactionID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	}

	data := client.encodeMessage(msg)

	// 最小ヘッダーサイズをチェック
	assert.GreaterOrEqual(t, len(data), 20, "Encoded message should be at least 20 bytes")

	// メッセージタイプをチェック
	assert.Equal(t, byte(0x00), data[0], "Wrong message type byte 0")
	assert.Equal(t, byte(0x01), data[1], "Wrong message type byte 1")

	// Magic Cookieをチェック
	expectedMagicCookie := []byte{0x21, 0x12, 0xA4, 0x42}
	assert.Equal(t, expectedMagicCookie, data[4:8], "Wrong magic cookie")
}

func TestSTUNMessageDecoding(t *testing.T) {
	client, err := NewSTUNClient()
	require.NoError(t, err, "NewSTUNClient() should not fail")
	defer client.Close()

	// 基本的なSTUNレスポンスメッセージを作成
	data := make([]byte, 20)
	data[0] = 0x01 // Binding Response
	data[1] = 0x01
	data[2] = 0x00 // Length = 0
	data[3] = 0x00
	data[4] = 0x21 // Magic Cookie
	data[5] = 0x12
	data[6] = 0xA4
	data[7] = 0x42
	// Transaction ID
	for i := 8; i < 20; i++ {
		data[i] = byte(i - 7)
	}

	msg, err := client.decodeMessage(data)
	require.NoError(t, err, "decodeMessage() should not fail")

	assert.Equal(t, BindingResponse, msg.MessageType, "Wrong message type")
}

func TestSTUNMessageDecodingRejectsInvalidMagicCookie(t *testing.T) {
	client, err := NewSTUNClient()
	require.NoError(t, err, "NewSTUNClient() should not fail")
	defer client.Close()

	// Magic Cookie が不正な（STUN ではない）パケット
	data := make([]byte, 20)
	data[0] = 0x01
	data[1] = 0x01
	data[4] = 0xDE // 不正な Magic Cookie
	data[5] = 0xAD
	data[6] = 0xBE
	data[7] = 0xEF

	_, err = client.decodeMessage(data)
	assert.Error(t, err, "decodeMessage() should reject invalid magic cookie")
}

func TestSTUNMessageDecodingRejectsInvalidMessageLength(t *testing.T) {
	client, err := NewSTUNClient()
	require.NoError(t, err, "NewSTUNClient() should not fail")
	defer client.Close()

	// Message Length がパケットサイズを超えている
	data := make([]byte, 20)
	data[0] = 0x01
	data[1] = 0x01
	data[2] = 0x00
	data[3] = 0x08 // Length = 8 だが実データは 0 バイト
	copy(data[4:8], STUNMagicCookieBytes)

	_, err = client.decodeMessage(data)
	assert.Error(t, err, "decodeMessage() should reject message length exceeding packet size")
}

func TestSTUNMessageDecodingIgnoresTrailingData(t *testing.T) {
	client, err := NewSTUNClient()
	require.NoError(t, err, "NewSTUNClient() should not fail")
	defer client.Close()

	// Message Length = 0 だがパケット末尾に余分なデータがある
	data := make([]byte, 24)
	data[0] = 0x01
	data[1] = 0x01
	copy(data[4:8], STUNMagicCookieBytes)
	data[20] = 0xFF // 余分なデータ

	msg, err := client.decodeMessage(data)
	require.NoError(t, err, "decodeMessage() should not fail")
	assert.Empty(t, msg.Attributes, "trailing data should not be parsed as attributes")
}

func TestReadResponseDiscardsUnmatchedPackets(t *testing.T) {
	client, err := NewSTUNClient()
	require.NoError(t, err, "NewSTUNClient() should not fail")
	defer client.Close()

	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	defer sender.Close()

	clientPort := client.conn.LocalAddr().(*net.UDPAddr).Port
	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: clientPort}

	wantTxID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	wrongTxID := [12]byte{99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99}

	makeResponse := func(txID [12]byte) []byte {
		data := make([]byte, 20)
		data[0] = 0x01 // Binding Response
		data[1] = 0x01
		copy(data[4:8], STUNMagicCookieBytes)
		copy(data[8:20], txID[:])
		return data
	}

	// 1. STUN ではないパケット → 読み捨てられる
	_, err = sender.WriteToUDP([]byte("not a stun packet"), clientAddr)
	require.NoError(t, err)
	// 2. Transaction ID が一致しない応答 → 読み捨てられる
	_, err = sender.WriteToUDP(makeResponse(wrongTxID), clientAddr)
	require.NoError(t, err)
	// 3. Transaction ID が一致する応答 → これが返る
	_, err = sender.WriteToUDP(makeResponse(wantTxID), clientAddr)
	require.NoError(t, err)

	msg, from, err := client.readResponse(time.Now().Add(2*time.Second), wantTxID)
	require.NoError(t, err, "readResponse() should return the matching response")
	assert.Equal(t, wantTxID, msg.TransactionID)
	assert.Equal(t, sender.LocalAddr().(*net.UDPAddr).Port, from.Port)
}

func TestRoundTripRetransmits(t *testing.T) {
	client, err := NewSTUNClient()
	require.NoError(t, err, "NewSTUNClient() should not fail")
	defer client.Close()

	// 1回目のリクエストを無視し、2回目に応答するフェイクサーバー
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	defer server.Close()

	go func() {
		buffer := make([]byte, 1500)
		for i := 0; ; i++ {
			n, from, err := server.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if i == 0 {
				continue // 1回目はパケットロスを模擬して無視
			}
			response := make([]byte, 20)
			response[0] = 0x01 // Binding Response
			response[1] = 0x01
			copy(response[4:8], STUNMagicCookieBytes)
			copy(response[8:20], buffer[8:20]) // txID をエコー
			server.WriteToUDP(response, from)
			_ = n
			return
		}
	}()

	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	request := client.encodeMessage(STUNMessage{
		MessageType:   BindingRequest,
		TransactionID: txID,
	})

	msg, _, err := client.roundTrip(server.LocalAddr().(*net.UDPAddr), request, txID)
	require.NoError(t, err, "roundTrip() should succeed after retransmission")
	assert.Equal(t, BindingResponse, msg.MessageType)
	assert.Equal(t, txID, msg.TransactionID)
}

func TestExtractErrorCode(t *testing.T) {
	tests := []struct {
		name         string
		attrValue    []byte
		expectedCode int
		expectedMsg  string
	}{
		{
			name:         "Error 420 - Unknown Attribute",
			attrValue:    []byte{0x00, 0x00, 0x04, 0x14, 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e'},
			expectedCode: 420,
			expectedMsg:  "Unknown Attribute",
		},
		{
			name:         "Error 400 - Bad Request",
			attrValue:    []byte{0x00, 0x00, 0x04, 0x00, 'B', 'a', 'd', ' ', 'R', 'e', 'q', 'u', 'e', 's', 't'},
			expectedCode: 400,
			expectedMsg:  "Bad Request",
		},
		{
			name:         "Error 500 - Server Error",
			attrValue:    []byte{0x00, 0x00, 0x05, 0x00},
			expectedCode: 500,
			expectedMsg:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg := &STUNMessage{
				MessageType:   BindingErrorResponse,
				TransactionID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Attributes: []STUNAttribute{
					{
						Type:   ErrorCode,
						Length: uint16(len(test.attrValue)),
						Value:  test.attrValue,
					},
				},
			}

			code, reason := extractErrorCode(msg)
			assert.Equal(t, test.expectedCode, code, "Unexpected error code")
			assert.Equal(t, test.expectedMsg, reason, "Unexpected error message")
		})
	}
}

func TestIsChangeRequestUnsupportedError(t *testing.T) {
	tests := []struct {
		name       string
		errorCode  int
		shouldFail bool
	}{
		{
			name:       "Error 420 - CHANGE-REQUEST unsupported",
			errorCode:  420,
			shouldFail: true,
		},
		{
			name:       "Error 400 - Other error",
			errorCode:  400,
			shouldFail: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// エラーコードを構築
			class := test.errorCode / 100
			number := test.errorCode % 100
			attrValue := []byte{0x00, 0x00, byte(class), byte(number)}

			msg := &STUNMessage{
				MessageType:   BindingErrorResponse,
				TransactionID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Attributes: []STUNAttribute{
					{
						Type:   ErrorCode,
						Length: 4,
						Value:  attrValue,
					},
				},
			}

			result := isChangeRequestUnsupportedError(msg)
			assert.Equal(t, test.shouldFail, result)
		})
	}
}
