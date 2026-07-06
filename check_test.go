package natchecker

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

func TestNATFilteringTypeString(t *testing.T) {
	tests := []struct {
		filteringType NATFilteringType
		expected      string
	}{
		{EndpointIndependentFiltering, "Endpoint Independent Filtering"},
		{AddressDependentFiltering, "Address Dependent Filtering"},
		{AddressPortDependentFiltering, "Address and Port Dependent Filtering"},
		{FilteringUnknown, "Unknown"},
	}

	for _, test := range tests {
		result := test.filteringType.String()
		assert.Equal(t, test.expected, result, "NATFilteringType(%d).String()", test.filteringType)
	}
}

func TestDetailedNATType(t *testing.T) {
	tests := []struct {
		name         string
		detailedType DetailedNATType
		expectedName string
		expectedStr  string
	}{
		{
			name:         "Full Cone NAT",
			detailedType: DetailedNATType{Mapping: EndpointIndependent, Filtering: EndpointIndependentFiltering},
			expectedName: "Full Cone NAT",
			expectedStr:  "Endpoint Independent Mapping / Endpoint Independent Filtering",
		},
		{
			name:         "Restricted Cone NAT",
			detailedType: DetailedNATType{Mapping: EndpointIndependent, Filtering: AddressDependentFiltering},
			expectedName: "Restricted Cone NAT",
			expectedStr:  "Endpoint Independent Mapping / Address Dependent Filtering",
		},
		{
			name:         "Port Restricted Cone NAT",
			detailedType: DetailedNATType{Mapping: EndpointIndependent, Filtering: AddressPortDependentFiltering},
			expectedName: "Port Restricted Cone NAT",
			expectedStr:  "Endpoint Independent Mapping / Address and Port Dependent Filtering",
		},
		{
			name:         "Symmetric NAT (Address Dependent Mapping)",
			detailedType: DetailedNATType{Mapping: AddressDependent, Filtering: AddressDependentFiltering},
			expectedName: "Symmetric NAT",
			expectedStr:  "Address Dependent Mapping / Address Dependent Filtering",
		},
		{
			name:         "Symmetric NAT (Address and Port Dependent Mapping)",
			detailedType: DetailedNATType{Mapping: AddressPortDependent, Filtering: AddressPortDependentFiltering},
			expectedName: "Symmetric NAT",
			expectedStr:  "Address and Port Dependent Mapping / Address and Port Dependent Filtering",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedName, test.detailedType.LegacyName())
			assert.Equal(t, test.expectedStr, test.detailedType.String())
		})
	}
}

func TestDetermineNATType(t *testing.T) {
	tests := []struct {
		name     string
		mapping1 *net.UDPAddr // Test I: 主アドレス宛
		mapping2 *net.UDPAddr // Test II: 代替IP・主ポート宛
		mapping3 *net.UDPAddr // Test III: 代替IP・代替ポート宛
		expected NATMappingType
	}{
		{
			name:     "Endpoint Independent - same mapping for different destination IPs",
			mapping1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mapping2: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mapping3: nil, // Test I と Test II が一致した場合 Test III は実行されない
			expected: EndpointIndependent,
		},
		{
			name:     "Address Dependent - mapping changes with IP but not with port",
			mapping1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mapping2: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 54321},
			mapping3: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 54321},
			expected: AddressDependent,
		},
		{
			name:     "Address Port Dependent - mapping changes with every destination",
			mapping1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mapping2: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 54321},
			mapping3: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 67890},
			expected: AddressPortDependent,
		},
		{
			name: "same port but different external IP is not Endpoint Independent",
			// 外部 IP プールを持つ CGN 等: ポートが同じでも IP が違えば別マッピング
			mapping1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mapping2: &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 12345},
			mapping3: &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 12345},
			expected: AddressPortDependent,
		},
		{
			name:     "Address Dependent detected by IP+port comparison",
			mapping1: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			mapping2: &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 12345},
			mapping3: &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 12345},
			expected: AddressDependent,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := determineNATType(test.mapping1, test.mapping2, test.mapping3)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestUDPAddrEqual(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345}

	assert.True(t, udpAddrEqual(addr, &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345}))
	assert.False(t, udpAddrEqual(addr, &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 12345}), "IP が異なれば別マッピング")
	assert.False(t, udpAddrEqual(addr, &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 54321}), "ポートが異なれば別マッピング")
	assert.False(t, udpAddrEqual(addr, nil))
	assert.False(t, udpAddrEqual(nil, addr))
}

func TestWithDefaultPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"stun.cloudflare.com", "stun.cloudflare.com:3478"},
		{"stun.cloudflare.com:19302", "stun.cloudflare.com:19302"},
		{"192.0.2.1", "192.0.2.1:3478"},
		{"192.0.2.1:3479", "192.0.2.1:3479"},
		{"2001:db8::1", "[2001:db8::1]:3478"},
		{"[2001:db8::1]:19302", "[2001:db8::1]:19302"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			assert.Equal(t, test.expected, withDefaultPort(test.input))
		})
	}
}

func TestCheckMappingResponse(t *testing.T) {
	// CheckMappingResultの構造体テスト
	result := &CheckMappingResult{
		NATType: EndpointIndependent,
		Response: CheckMappingResponseData{
			OtherAddress: &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 3479},
			Mapping1:     &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
			Mapping2:     &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
		},
	}

	assert.Equal(t, EndpointIndependent, result.NATType)
	assert.Equal(t, "198.51.100.1:3479", result.Response.OtherAddress.String())
	assert.Equal(t, "203.0.113.1:12345", result.Response.Mapping1.String())
	assert.Equal(t, "203.0.113.1:12345", result.Response.Mapping2.String())
	assert.Nil(t, result.Response.Mapping3)
}

// 統合テスト - INTEGRATION=1 環境変数が設定されている場合のみ実行
func TestCheckMappingTypeIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("Skipping integration test. Set INTEGRATION=1 to run.")
	}

	// マッピング判定には OTHER-ADDRESS (RFC 5780) 対応サーバーが必要
	server := "stunserver2025.stunprotocol.org"

	result, err := CheckMappingType(server)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Test I のマッピング結果が設定されていることを確認
	require.NotNil(t, result.Response.Mapping1)
	assert.NotNil(t, result.Response.Mapping1.IP)
	assert.Greater(t, result.Response.Mapping1.Port, 0)

	// OTHER-ADDRESS 対応サーバーであれば具体的なタイプが判定される
	if result.Response.OtherAddress != nil {
		validTypes := []NATMappingType{EndpointIndependent, AddressDependent, AddressPortDependent}
		assert.Contains(t, validTypes, result.NATType)
		assert.NotNil(t, result.Response.Mapping2)
	} else {
		assert.Equal(t, Unknown, result.NATType)
	}

	t.Logf("=== Mapping Detection Test ===")
	t.Logf("Server: %s", server)
	t.Logf("Detected NAT mapping type: %s", result.NATType)
	t.Logf("NoNAT: %v", result.NoNAT)
	t.Logf("LocalAddress: %s", result.Response.LocalAddress)
	t.Logf("OtherAddress: %s", result.Response.OtherAddress)
	t.Logf("Mapping1: %s", result.Response.Mapping1)
	t.Logf("Mapping2: %s", result.Response.Mapping2)
	t.Logf("Mapping3: %s", result.Response.Mapping3)
}

// 統合テスト - フィルタリング判定
func TestCheckFilteringBehaviorIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("Skipping integration test. Set INTEGRATION=1 to run.")
	}

	// RFC 5780対応のSTUNサーバーを試す
	// stunserver2025.stunprotocol.org は RFC 5780 (Stuntman実装) に対応
	servers := []string{
		"stunserver2025.stunprotocol.org",
	}

	var result *CheckFilteringResult
	var err error
	var usedServer string

	// いずれかのサーバーで成功するまで試す
	for _, server := range servers {
		result, err = CheckFilteringBehavior(server)
		if err == nil {
			usedServer = server
			break
		}
		t.Logf("Server %s failed: %v", server, err)
	}

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("=== Filtering Detection Test ===")
	t.Logf("Server: %s", usedServer)
	t.Logf("Filtering Type: %s", result.FilteringType)
	t.Logf("Supports CHANGE-REQUEST: %v", result.ServerSupport.SupportsChangeRequest)
	t.Logf("Supports OTHER-ADDRESS: %v", result.ServerSupport.SupportsOtherAddress)
	t.Logf("Test II Response: %v", result.Response.TestIIResponse)
	t.Logf("Test III Response: %v", result.Response.TestIIIResponse)

	if result.Response.OtherAddress != nil {
		t.Logf("Other Address: %s", result.Response.OtherAddress)
	}

	// FilteringUnknownは正常な結果
	// RFC 5780: "If the OTHER-ADDRESS is not returned, the server does not
	//            support this usage and this test cannot be run."
	// ほとんどの公開STUNサーバーはOTHER-ADDRESSやCHANGE-REQUESTを
	// サポートしていないため、FilteringUnknownになることが多い
	if result.FilteringType == FilteringUnknown {
		t.Logf("Note: Filtering is Unknown (expected for most public STUN servers)")
		t.Logf("      Most public STUN servers do not support OTHER-ADDRESS or CHANGE-REQUEST attributes")
	}
}

// 統合テスト - 包括的NAT判定
func TestFullNATDetectionIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("Skipping integration test. Set INTEGRATION=1 to run.")
	}

	// マッピング・フィルタリングとも RFC 5780
	// (OTHER-ADDRESS/CHANGE-REQUEST) 対応サーバーが必要
	server := "stunserver2025.stunprotocol.org"

	result, err := FullNATDetection(server)
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("=== Full NAT Detection Result ===")
	t.Logf("Server: %s", server)
	t.Logf("")
	t.Logf("Detailed Type: %s", result.DetailedType)
	t.Logf("Legacy Name: %s", result.DetailedType.LegacyName())
	t.Logf("\n--- Mapping ---")
	t.Logf("Mapping Type: %s", result.MappingResult.NATType)
	t.Logf("Mapping1: %s", result.MappingResult.Response.Mapping1)
	t.Logf("Mapping2: %s", result.MappingResult.Response.Mapping2)
	t.Logf("Mapping3: %s", result.MappingResult.Response.Mapping3)
	t.Logf("\n--- Filtering ---")
	t.Logf("Filtering Type: %s", result.FilteringResult.FilteringType)
	t.Logf("Supports CHANGE-REQUEST: %v", result.FilteringResult.ServerSupport.SupportsChangeRequest)
	t.Logf("Supports OTHER-ADDRESS: %v", result.FilteringResult.ServerSupport.SupportsOtherAddress)
}
