package main

import (
	"fmt"
	"net"
)

// NATマッピングタイプ
type NATMappingType int

const (
	EndpointIndependent NATMappingType = iota
	AddressDependent
	AddressPortDependent
	Unknown
)

func (n NATMappingType) String() string {
	switch n {
	case EndpointIndependent:
		return "Endpoint Independent Mapping"
	case AddressDependent:
		return "Address Dependent Mapping"
	case AddressPortDependent:
		return "Address and Port Dependent Mapping"
	default:
		return "Unknown"
	}
}

// NATフィルタリングタイプ (RFC 5780)
type NATFilteringType int

const (
	EndpointIndependentFiltering NATFilteringType = iota
	AddressDependentFiltering
	AddressPortDependentFiltering
	FilteringUnknown
)

func (n NATFilteringType) String() string {
	switch n {
	case EndpointIndependentFiltering:
		return "Endpoint Independent Filtering"
	case AddressDependentFiltering:
		return "Address Dependent Filtering"
	case AddressPortDependentFiltering:
		return "Address and Port Dependent Filtering"
	default:
		return "Unknown"
	}
}

// DetailedNATType はマッピングとフィルタリングの組み合わせによる詳細なNATタイプ
type DetailedNATType struct {
	Mapping   NATMappingType
	Filtering NATFilteringType
}

// String はRFC 5780準拠の分類名を返す
func (d DetailedNATType) String() string {
	return fmt.Sprintf("%s / %s", d.Mapping, d.Filtering)
}

// LegacyName はレガシーなNAT分類名（Full Cone, Symmetric等）を返す
//
// RFC 3489で定義された古典的なNAT分類方式にマッピングします。
// RFC 4787とRFC 5780では、より詳細な2軸分類（Mapping × Filtering）を採用していますが、
// 後方互換性のために従来の4種類の分類名を提供します：
//
//   Full Cone NAT           : EI Mapping + EI Filtering
//   Restricted Cone NAT     : EI Mapping + AD Filtering
//   Port Restricted Cone NAT: EI Mapping + APD Filtering
//   Symmetric NAT           : AD Mapping または APD Mapping（フィルタリングに依らず）
//
// (EI=Endpoint Independent, AD=Address Dependent, APD=Address and Port Dependent)
func (d DetailedNATType) LegacyName() string {
	// Endpoint Independent Mapping + Endpoint Independent Filtering = Full Cone NAT
	// RFC 3489: すべての外部ホストが同じ内部アドレス:ポートに到達可能
	if d.Mapping == EndpointIndependent && d.Filtering == EndpointIndependentFiltering {
		return "Full Cone NAT"
	}

	// Endpoint Independent Mapping + Address Dependent Filtering = Restricted Cone NAT
	// RFC 3489: 内部ホストが通信したことのある外部IPからのみパケットを受信可能
	if d.Mapping == EndpointIndependent && d.Filtering == AddressDependentFiltering {
		return "Restricted Cone NAT"
	}

	// Endpoint Independent Mapping + Address and Port Dependent Filtering = Port Restricted Cone NAT
	// RFC 3489: 内部ホストが通信したことのある外部IP:Portからのみパケットを受信可能
	if d.Mapping == EndpointIndependent && d.Filtering == AddressPortDependentFiltering {
		return "Port Restricted Cone NAT"
	}

	// Address Dependent または Address and Port Dependent Mapping = Symmetric NAT
	// RFC 3489: 宛先ごとに異なるマッピングを使用、P2P通信が困難
	if d.Mapping == AddressDependent || d.Mapping == AddressPortDependent {
		return "Symmetric NAT"
	}

	return "Unknown NAT Type"
}

// STUNServerSupportInfo はSTUNサーバーの機能サポート情報
type STUNServerSupportInfo struct {
	SupportsChangeRequest bool
	SupportsOtherAddress  bool
}

// CheckFilteringResponseData はフィルタリング判定の詳細データ
type CheckFilteringResponseData struct {
	OtherAddress      *net.UDPAddr // Test I で取得した代替アドレス
	TestIIResponse    bool         // Test II (Change IP+Port) でレスポンスを受信したか
	TestIIIResponse   bool         // Test III (Change Port) でレスポンスを受信したか
}

// CheckFilteringResult はフィルタリング判定の結果
type CheckFilteringResult struct {
	FilteringType NATFilteringType
	Response      CheckFilteringResponseData
	ServerSupport STUNServerSupportInfo
}

// FullNATDetectionResult は包括的なNAT判定結果
type FullNATDetectionResult struct {
	DetailedType    DetailedNATType
	MappingResult   *CheckMappingResult
	FilteringResult *CheckFilteringResult
}

// String は結果の文字列表現を返す
func (f FullNATDetectionResult) String() string {
	return fmt.Sprintf("NAT Type: %s (%s)", f.DetailedType.LegacyName(), f.DetailedType)
}

// CheckMappingResult はNATマッピングタイプ判定の結果を含む構造体
type CheckMappingResult struct {
	NATType  NATMappingType           `json:"nat_type"`
	Response CheckMappingResponseData `json:"response"`
}

// CheckMappingResponseData はマッピング結果の詳細データを含む構造体
type CheckMappingResponseData struct {
	MappingA1 *net.UDPAddr `json:"mapping_a1"` // サーバーAからの1回目のマッピング
	MappingB1 *net.UDPAddr `json:"mapping_b1"` // サーバーBからの1回目のマッピング
	MappingA2 *net.UDPAddr `json:"mapping_a2"` // サーバーAからの2回目のマッピング
}

// CheckMappingType は2つのSTUNサーバーを使ってNATマッピングタイプを判定します
func CheckMappingType(serverIpA, serverIpB string) (*CheckMappingResult, error) {
	client, err := NewSTUNClient()
	if err != nil {
		return nil, fmt.Errorf("STUNクライアント作成エラー: %w", err)
	}
	defer client.Close()

	// 複数のポートを試す
	ports := []string{":3478", ":19302"}

	var mappingA1, mappingB1, mappingA2 *net.UDPAddr

	// テスト1: サーバーAから基本的なマッピングを取得
	for _, port := range ports {
		mappingA1, err = client.SendBindingRequest(serverIpA+port, false, false)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("サーバーAへのリクエスト失敗: %w", err)
	}

	// テスト2: サーバーBから基本的なマッピングを取得
	for _, port := range ports {
		mappingB1, err = client.SendBindingRequest(serverIpB+port, false, false)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("サーバーBへのリクエスト失敗: %w", err)
	}

	// テスト3: 同じサーバーAに再度リクエスト（一貫性確認）
	for _, port := range ports {
		mappingA2, err = client.SendBindingRequest(serverIpA+port, false, false)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("サーバーAへの2回目リクエスト失敗: %w", err)
	}

	// マッピングタイプ判定
	natType := determineNATType(mappingA1, mappingB1, mappingA2)

	return &CheckMappingResult{
		NATType: natType,
		Response: CheckMappingResponseData{
			MappingA1: mappingA1,
			MappingB1: mappingB1,
			MappingA2: mappingA2,
		},
	}, nil
}

func determineNATType(mappingA1, mappingB1, mappingA2 *net.UDPAddr) NATMappingType {
	// 同じサーバーへの複数回のリクエストで一貫性をチェック
	if mappingA1.Port != mappingA2.Port {
		return AddressPortDependent
	}

	// 異なるサーバーへのリクエストでマッピングを比較
	if mappingA1.Port == mappingB1.Port {
		return EndpointIndependent
	} else {
		return AddressDependent
	}
}

// CheckFilteringBehavior はNATフィルタリング動作を判定します
// RFC 5780 Section 4.3: Determining NAT Filtering Behavior
//
// このテストは、NATがどの条件で外部からのパケットを許可するかを判定します。
// 3種類のフィルタリング動作（RFC 4787より）：
//   - Endpoint-Independent Filtering: すべての外部アドレスからのパケットを許可
//   - Address-Dependent Filtering: 通信済みIPアドレスからのみ許可
//   - Address and Port-Dependent Filtering: 通信済みIP:ポートのみ許可
func CheckFilteringBehavior(serverAddr string) (*CheckFilteringResult, error) {
	client, err := NewSTUNClient()
	if err != nil {
		return nil, fmt.Errorf("STUNクライアント作成エラー: %w", err)
	}
	defer client.Close()

	// 複数のポートを試す
	ports := []string{":3478", ":19302"}

	var otherAddr *net.UDPAddr
	var serverWithPort string

	// Test I: 基本的なBinding Requestを送信し、OTHER-ADDRESSを取得
	// RFC 5780: "The client performs a UDP connectivity check by sending
	//            a STUN Binding Request to the server."
	// レスポンスに含まれるOTHER-ADDRESSは、サーバーの代替IP:Portを示す
	for _, port := range ports {
		serverWithPort = serverAddr + port
		otherAddr, err = client.GetAlternateAddress(serverWithPort)
		if err == nil {
			break
		}
	}

	result := &CheckFilteringResult{
		ServerSupport: STUNServerSupportInfo{
			SupportsOtherAddress: otherAddr != nil,
		},
		Response: CheckFilteringResponseData{
			OtherAddress: otherAddr,
		},
	}

	// OTHER-ADDRESSが取得できない場合、フィルタリング判定は不可能
	if otherAddr == nil {
		result.FilteringType = FilteringUnknown
		return result, nil
	}

	// Test II: CHANGE-REQUEST属性でIP+Port両方の変更を要求
	// RFC 5780: "The client sends a Binding Request to the server,
	//            with both the 'change IP' and 'change port' flags set."
	// サーバーは代替IP:Portから応答を送信する
	// レスポンスを受信 → Endpoint-Independent Filtering
	// タイムアウト → Test IIIへ進む
	testIIAddr, testIIErr := client.SendBindingRequest(serverWithPort, true, true)
	result.Response.TestIIResponse = (testIIErr == nil && testIIAddr != nil)

	// Test II でレスポンスがあった場合: Endpoint Independent Filtering
	if result.Response.TestIIResponse {
		result.FilteringType = EndpointIndependentFiltering
		result.ServerSupport.SupportsChangeRequest = true
		return result, nil
	}

	// Test II でエラーレスポンス（エラーコード420等）を受信した場合
	// CHANGE-REQUEST非対応サーバーと判断し、フィルタリング判定は不可能
	// ただし、タイムアウトエラーの場合は Test III に進む必要がある
	if testIIErr != nil {
		// タイムアウトエラーかどうかをチェック
		if netErr, ok := testIIErr.(net.Error); ok && netErr.Timeout() {
			// タイムアウトの場合は Test III に進む（正常な動作）
		} else {
			// STUN エラーレスポンス（420等）の場合はサーバー非対応と判断
			result.FilteringType = FilteringUnknown
			result.ServerSupport.SupportsChangeRequest = false
			return result, nil
		}
	}

	// Test III: CHANGE-REQUEST属性でPortのみの変更を要求
	// RFC 5780: "The client sends a Binding Request with only
	//            the 'change port' flag set."
	// サーバーは同じIPの異なるポートから応答を送信する
	// レスポンスを受信 → Address-Dependent Filtering
	// タイムアウト → Address and Port-Dependent Filtering
	testIIIAddr, testIIIErr := client.SendBindingRequest(serverWithPort, false, true)
	result.Response.TestIIIResponse = (testIIIErr == nil && testIIIAddr != nil)

	// Test III でレスポンスがあった場合: Address Dependent Filtering
	if result.Response.TestIIIResponse {
		result.FilteringType = AddressDependentFiltering
		result.ServerSupport.SupportsChangeRequest = true
		return result, nil
	}

	// Test II と Test III の両方でタイムアウト: Address and Port Dependent Filtering
	// RFC 5780: "If no response is received, the filtering behavior is
	//            Address and Port-Dependent."
	result.FilteringType = AddressPortDependentFiltering
	result.ServerSupport.SupportsChangeRequest = true
	return result, nil
}

// FullNATDetection はRFC 5780準拠の包括的なNAT判定を実行します
//
// RFC 5780: "This specification defines an experimental usage of the
//            Session Traversal Utilities for NAT (STUN) Protocol that
//            discovers the presence and current behavior of NATs and firewalls
//            between the STUN client and the STUN server."
//
// NATを2つの独立した動作で分類します（RFC 4787）：
//   1. Mapping Behavior: NATがどのように外部アドレス:ポートを割り当てるか
//   2. Filtering Behavior: NATがどのように外部からのパケットをフィルタリングするか
//
// この組み合わせにより、以下の9種類のNATタイプに分類されます：
//   - 3種類のマッピング × 3種類のフィルタリング = 9通り
func FullNATDetection(serverIpA, serverIpB string) (*FullNATDetectionResult, error) {
	// Phase 1: マッピング判定
	// RFC 5780 Section 4.2: Determining NAT Mapping Behavior
	mappingResult, err := CheckMappingType(serverIpA, serverIpB)
	if err != nil {
		return nil, fmt.Errorf("マッピング判定エラー: %w", err)
	}

	// Phase 2: フィルタリング判定
	// RFC 5780 Section 4.3: Determining NAT Filtering Behavior
	filteringResult, err := CheckFilteringBehavior(serverIpA)
	if err != nil {
		return nil, fmt.Errorf("フィルタリング判定エラー: %w", err)
	}

	// Phase 3: 結果を統合してDetailedNATTypeを生成
	detailedType := DetailedNATType{
		Mapping:   mappingResult.NATType,
		Filtering: filteringResult.FilteringType,
	}

	return &FullNATDetectionResult{
		DetailedType:    detailedType,
		MappingResult:   mappingResult,
		FilteringResult: filteringResult,
	}, nil
}
