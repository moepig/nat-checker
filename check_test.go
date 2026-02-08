package main

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNATMappingTypeString(t *testing.T) {
	tests := []struct {
		natType  NATMappingType
		expected string
	}{
		{EndpointIndependent, "Endpoint Independent Mapping"},
		{AddressDependent, "Address Dependent Mapping"},
		{AddressPortDependent, "Address and Port Dependent Mapping"},
		{Unknown, "Unknown"},
	}

	for _, test := range tests {
		result := test.natType.String()
		assert.Equal(t, test.expected, result, "NATMappingType(%d).String()", test.natType)
	}
}

func TestDetermineNATType(t *testing.T) {
	tests := []struct {
		name      string
		mappingA1 *net.UDPAddr
		mappingB1 *net.UDPAddr
		mappingA2 *net.UDPAddr
		expected  NATMappingType
	}{
		{
			name:      "Endpoint Independent - same port for different servers",
			mappingA1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mappingB1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mappingA2: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			expected:  EndpointIndependent,
		},
		{
			name:      "Address Dependent - different port for different servers",
			mappingA1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mappingB1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 54321},
			mappingA2: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			expected:  AddressDependent,
		},
		{
			name:      "Address Port Dependent - inconsistent port for same server",
			mappingA1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mappingB1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 54321},
			mappingA2: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 67890},
			expected:  AddressPortDependent,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := determineNATType(test.mappingA1, test.mappingB1, test.mappingA2)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestCheckMappingResponse(t *testing.T) {
	// CheckMappingResultの構造体テスト
	result := &CheckMappingResult{
		NATType: EndpointIndependent,
		Response: CheckMappingResponseData{
			MappingA1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			MappingB1: &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 12345},
			MappingA2: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
		},
	}

	assert.Equal(t, EndpointIndependent, result.NATType)
	assert.Equal(t, "203.0.113.1:12345", result.Response.MappingA1.String())
	assert.Equal(t, "203.0.113.2:12345", result.Response.MappingB1.String())
	assert.Equal(t, "203.0.113.1:12345", result.Response.MappingA2.String())
}

// 統合テスト - INTEGRATION=1 環境変数が設定されている場合のみ実行
func TestCheckMappingTypeIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("Skipping integration test. Set INTEGRATION=1 to run.")
	}

	// 複数のSTUNサーバーを試す
	serverPairs := []string{"stun.cloudflare.com", "stun1.l.google.com"}

	var result *CheckMappingResult
	var err error
	
	result, err = CheckMappingType(serverPairs[0], serverPairs[1])

	require.NoError(t, err)
	require.NotNil(t, result)

	// 有効なNATタイプが返されることを確認
	validTypes := []NATMappingType{EndpointIndependent, AddressDependent, AddressPortDependent}
	assert.Contains(t, validTypes, result.NATType)

	// マッピング結果が設定されていることを確認
	assert.NotNil(t, result.Response.MappingA1)
	assert.NotNil(t, result.Response.MappingB1)
	assert.NotNil(t, result.Response.MappingA2)

	// IPアドレスとポートが有効であることを確認
	assert.NotNil(t, result.Response.MappingA1.IP)
	assert.Greater(t, result.Response.MappingA1.Port, 0)
	assert.NotNil(t, result.Response.MappingB1.IP)
	assert.Greater(t, result.Response.MappingB1.Port, 0)
	assert.NotNil(t, result.Response.MappingA2.IP)
	assert.Greater(t, result.Response.MappingA2.Port, 0)

	t.Logf("Detected NAT mapping type: %s", result.NATType)
	t.Logf("MappingA1: %s", result.Response.MappingA1)
	t.Logf("MappingB1: %s", result.Response.MappingB1)
	t.Logf("MappingA2: %s", result.Response.MappingA2)
}