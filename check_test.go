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

// 統合テスト - フィルタリング判定
func TestCheckFilteringBehaviorIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("Skipping integration test. Set INTEGRATION=1 to run.")
	}

	// RFC 5780対応のSTUNサーバーを試す
	// 注意: ほとんどの公開STUNサーバーはRFC 5780に完全対応していないため、
	//       FilteringUnknownが返されることが多い（これは正常な動作）
	servers := []string{
		"stun.cloudflare.com",
		"stun1.l.google.com",
		"stun.ekiga.net",
	}

	var result *CheckFilteringResult
	var err error

	// いずれかのサーバーで成功するまで試す
	for _, server := range servers {
		result, err = CheckFilteringBehavior(server)
		if err == nil {
			break
		}
		t.Logf("Server %s failed: %v", server, err)
	}

	require.NoError(t, err)
	require.NotNil(t, result)

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
		t.Logf("      This is NOT an error. See FILTERING_UNKNOWN_ANALYSIS.md")
	}
}

// 統合テスト - 包括的NAT判定
func TestFullNATDetectionIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("Skipping integration test. Set INTEGRATION=1 to run.")
	}

	serverPairs := []string{"stun.cloudflare.com", "stun1.l.google.com"}

	result, err := FullNATDetection(serverPairs[0], serverPairs[1])
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("=== Full NAT Detection Result ===")
	t.Logf("Detailed Type: %s", result.DetailedType)
	t.Logf("Legacy Name: %s", result.DetailedType.LegacyName())
	t.Logf("\n--- Mapping ---")
	t.Logf("Mapping Type: %s", result.MappingResult.NATType)
	t.Logf("MappingA1: %s", result.MappingResult.Response.MappingA1)
	t.Logf("MappingB1: %s", result.MappingResult.Response.MappingB1)
	t.Logf("MappingA2: %s", result.MappingResult.Response.MappingA2)
	t.Logf("\n--- Filtering ---")
	t.Logf("Filtering Type: %s", result.FilteringResult.FilteringType)
	t.Logf("Supports CHANGE-REQUEST: %v", result.FilteringResult.ServerSupport.SupportsChangeRequest)
	t.Logf("Supports OTHER-ADDRESS: %v", result.FilteringResult.ServerSupport.SupportsOtherAddress)
}