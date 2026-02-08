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