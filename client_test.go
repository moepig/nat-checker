package main

import (
	"testing"

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