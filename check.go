package natchecker

import (
	"errors"
	"fmt"
	"net"
)

// isTimeoutError はエラーが受信タイムアウトかどうかを判定します
func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// defaultSTUNPort は STUN の標準ポート (RFC 8489 Section 8)
const defaultSTUNPort = "3478"

// withDefaultPort は "host" または "host:port" 形式のアドレスを受け取り、
// ポートが指定されていなければ STUN 標準ポート 3478 を補います。
// IPv6 リテラルは "[::1]:3478" のように角括弧付きで解釈されます。
func withDefaultPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, defaultSTUNPort)
}

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
//	Full Cone NAT           : EI Mapping + EI Filtering
//	Restricted Cone NAT     : EI Mapping + AD Filtering
//	Port Restricted Cone NAT: EI Mapping + APD Filtering
//	Symmetric NAT           : AD Mapping または APD Mapping（フィルタリングに依らず）
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
	OtherAddress    *net.UDPAddr // Test I で取得した代替アドレス
	TestIIResponse  bool         // Test II (Change IP+Port) で代替IPからのレスポンスを受信したか
	TestIIIResponse bool         // Test III (Change Port) で同一IP・別ポートからのレスポンスを受信したか
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
	OtherAddress *net.UDPAddr `json:"other_address"` // Test I で取得したサーバーの代替アドレス
	Mapping1     *net.UDPAddr `json:"mapping_1"`     // Test I: 主アドレス宛のマッピング
	Mapping2     *net.UDPAddr `json:"mapping_2"`     // Test II: 代替IP・主ポート宛のマッピング
	Mapping3     *net.UDPAddr `json:"mapping_3"`     // Test III: 代替IP・代替ポート宛のマッピング
}

// CheckMappingType はNATマッピングタイプを判定します
// RFC 5780 Section 4.3: Determining NAT Mapping Behavior
//
// serverAddr は "host" または "host:port" 形式で指定します。
// ポートを省略した場合は STUN 標準ポート 3478 が使われます。
//
// AD/APD の区別には「同じサーバーの別 IP・別ポート」宛の送信結果の比較が
// 必要なため、OTHER-ADDRESS (RFC 5780) をサポートするサーバーが必要です。
// 非対応サーバーの場合は NATType が Unknown になります。
//
//   - Test I:   主アドレス宛に Binding Request（OTHER-ADDRESS も同じ応答から取得）
//   - Test II:  代替 IP・主ポート宛に Binding Request
//     マッピングが Test I と同じ → Endpoint Independent
//   - Test III: 代替 IP・代替ポート宛に Binding Request
//     マッピングが Test II と同じ → Address Dependent、異なる → Address and Port Dependent
func CheckMappingType(serverAddr string) (*CheckMappingResult, error) {
	client, err := NewSTUNClient()
	if err != nil {
		return nil, fmt.Errorf("STUNクライアント作成エラー: %w", err)
	}
	defer client.Close()

	server := withDefaultPort(serverAddr)
	serverUDP, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("サーバーアドレス解決エラー: %w", err)
	}

	// Test I: 主アドレス宛に Binding Request
	// RFC 5780 Section 4.3: "the client performs the UDP connectivity check"
	test1, err := client.SendBindingRequest(server, false, false)
	if err != nil {
		return nil, fmt.Errorf("マッピング Test I 失敗: %w", err)
	}

	result := &CheckMappingResult{
		NATType: Unknown,
		Response: CheckMappingResponseData{
			Mapping1:     test1.MappedAddress,
			OtherAddress: test1.OtherAddress,
		},
	}

	// Test II/III には「同じサーバーの別 IP」宛の送信が必要。
	// OTHER-ADDRESS が無い、または主アドレスと IP が同じ場合は判定不可能
	other := test1.OtherAddress
	if other == nil || other.IP.Equal(serverUDP.IP) {
		return result, nil
	}

	// Test II: 代替 IP・主ポート宛に Binding Request
	// RFC 5780 Section 4.3: "the client sends a Binding Request to the
	// alternate address, but primary port"
	test2Target := (&net.UDPAddr{IP: other.IP, Port: serverUDP.Port}).String()
	test2, err := client.SendBindingRequest(test2Target, false, false)
	if err != nil {
		return result, fmt.Errorf("マッピング Test II 失敗: %w", err)
	}
	result.Response.Mapping2 = test2.MappedAddress

	// 宛先 IP が変わってもマッピングが同じ → Endpoint Independent
	if udpAddrEqual(test1.MappedAddress, test2.MappedAddress) {
		result.NATType = EndpointIndependent
		return result, nil
	}

	// Test III: 代替 IP・代替ポート宛に Binding Request
	// RFC 5780 Section 4.3: "the client sends a Binding Request to the
	// alternate address and port"
	test3, err := client.SendBindingRequest(other.String(), false, false)
	if err != nil {
		return result, fmt.Errorf("マッピング Test III 失敗: %w", err)
	}
	result.Response.Mapping3 = test3.MappedAddress

	result.NATType = determineNATType(test1.MappedAddress, test2.MappedAddress, test3.MappedAddress)
	return result, nil
}

// determineNATType は 3 つのテストで得られた外部マッピングから
// NATマッピングタイプを判定します (RFC 5780 Section 4.3)
//
// mapping1 は主アドレス宛、mapping2 は代替IP・主ポート宛、
// mapping3 は代替IP・代替ポート宛の送信で得られた外部マッピング。
// mapping1 と mapping2 が一致する場合、mapping3 は nil でもよい。
func determineNATType(mapping1, mapping2, mapping3 *net.UDPAddr) NATMappingType {
	// 宛先 IP が変わってもマッピングが同じ → Endpoint Independent
	if udpAddrEqual(mapping1, mapping2) {
		return EndpointIndependent
	}

	// 宛先 IP が同じままポートだけ変わってもマッピングが同じ → Address Dependent
	if udpAddrEqual(mapping2, mapping3) {
		return AddressDependent
	}

	return AddressPortDependent
}

// udpAddrEqual は 2 つの UDP アドレスを IP とポートの両方で比較します。
// ポートのみの比較では、外部 IP プールを持つ CGN などで異なる外部 IP に
// たまたま同じポートが割り当てられた場合に誤判定するため、必ず IP も比較する。
func udpAddrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

// CheckFilteringBehavior はNATフィルタリング動作を判定します
// RFC 5780 Section 4.4: Determining NAT Filtering Behavior
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

	serverWithPort := withDefaultPort(serverAddr)
	serverUDP, err := net.ResolveUDPAddr("udp", serverWithPort)
	if err != nil {
		return nil, fmt.Errorf("サーバーアドレス解決エラー: %w", err)
	}

	// Test I: 基本的なBinding Requestを送信し、OTHER-ADDRESSを取得
	// RFC 5780: "The client performs a UDP connectivity check by sending
	//            a STUN Binding Request to the server."
	// レスポンスに含まれるOTHER-ADDRESSは、サーバーの代替IP:Portを示す
	// XOR-MAPPED-ADDRESS と同じ Binding Response から 1 往復で取得する
	test1, err := client.SendBindingRequest(serverWithPort, false, false)
	if err != nil {
		return nil, fmt.Errorf("フィルタリング Test I 失敗: %w", err)
	}
	otherAddr := test1.OtherAddress

	result := &CheckFilteringResult{
		ServerSupport: STUNServerSupportInfo{
			SupportsOtherAddress: otherAddr != nil,
		},
		Response: CheckFilteringResponseData{
			OtherAddress: otherAddr,
		},
	}

	// OTHER-ADDRESSが取得できない場合、フィルタリング判定は不可能。
	// また Test II では「代替 IP からの応答」を確認する必要があるため、
	// 代替アドレスの IP が主アドレスと同じ場合も判定不可能
	if otherAddr == nil || otherAddr.IP.Equal(serverUDP.IP) {
		result.FilteringType = FilteringUnknown
		return result, nil
	}

	// Test II: CHANGE-REQUEST属性でIP+Port両方の変更を要求
	// RFC 5780: "The client sends a Binding Request to the server,
	//            with both the 'change IP' and 'change port' flags set."
	// サーバーは代替IP:Portから応答を送信する
	// 代替IPからのレスポンスを受信 → Endpoint-Independent Filtering
	// タイムアウト → Test IIIへ進む
	testII, testIIErr := client.SendBindingRequest(serverWithPort, true, true)

	if testIIErr == nil {
		// 応答が本当に「代替 IP」から来たことを検証する。
		// RFC 5780 は、OTHER-ADDRESS を返しつつ CHANGE-REQUEST を無視して
		// 主アドレスから応答するサーバーに対して、応答の送信元を確認せずに
		// Endpoint Independent Filtering と誤判定する危険を明示的に警告している
		if testII.ResponseFrom != nil && testII.ResponseFrom.IP.Equal(otherAddr.IP) {
			result.Response.TestIIResponse = true
			result.FilteringType = EndpointIndependentFiltering
			result.ServerSupport.SupportsChangeRequest = true
			return result, nil
		}

		// 主アドレスから応答が返った: CHANGE-REQUEST を無視するサーバーであり、
		// フィルタリング判定の根拠にできない
		result.FilteringType = FilteringUnknown
		result.ServerSupport.SupportsChangeRequest = false
		return result, nil
	}

	// Test II のエラー分類:
	//   - STUN エラーレスポンス（420 Unknown Attribute 等）
	//     → CHANGE-REQUEST 非対応サーバーと判断し、フィルタリング判定は不可能
	//   - タイムアウト → Test III に進む（正常な動作）
	//   - それ以外（ICMP unreachable、デコード失敗等）→ 判定不能としてエラーを返す
	{
		var stunErr *STUNError
		switch {
		case errors.As(testIIErr, &stunErr):
			result.FilteringType = FilteringUnknown
			result.ServerSupport.SupportsChangeRequest = false
			return result, nil
		case isTimeoutError(testIIErr):
			// Test III に進む
		default:
			return nil, fmt.Errorf("フィルタリング Test II 失敗: %w", testIIErr)
		}
	}

	// Test III: CHANGE-REQUEST属性でPortのみの変更を要求
	// RFC 5780: "The client sends a Binding Request with only
	//            the 'change port' flag set."
	// サーバーは同じIPの異なるポートから応答を送信する
	// 同じIP・異なるポートからのレスポンスを受信 → Address-Dependent Filtering
	// タイムアウト → Address and Port-Dependent Filtering
	testIII, testIIIErr := client.SendBindingRequest(serverWithPort, false, true)

	if testIIIErr == nil {
		// 応答が「主アドレスと同じ IP・異なるポート」から来たことを検証する
		if testIII.ResponseFrom != nil &&
			testIII.ResponseFrom.IP.Equal(serverUDP.IP) &&
			testIII.ResponseFrom.Port != serverUDP.Port {
			result.Response.TestIIIResponse = true
			result.FilteringType = AddressDependentFiltering
			result.ServerSupport.SupportsChangeRequest = true
			return result, nil
		}

		// 主アドレス:主ポートから応答が返った: CHANGE-REQUEST を無視するサーバー
		result.FilteringType = FilteringUnknown
		result.ServerSupport.SupportsChangeRequest = false
		return result, nil
	}

	// Test III のエラー分類（Test II と同様）
	{
		var stunErr *STUNError
		switch {
		case errors.As(testIIIErr, &stunErr):
			result.FilteringType = FilteringUnknown
			result.ServerSupport.SupportsChangeRequest = false
			return result, nil
		case isTimeoutError(testIIIErr):
			// フィルタリングされたと解釈して判定を続ける
		default:
			return nil, fmt.Errorf("フィルタリング Test III 失敗: %w", testIIIErr)
		}
	}

	// Test II と Test III の両方でタイムアウト: Address and Port Dependent Filtering
	// RFC 5780: "If no response is received, the filtering behavior is
	//            Address and Port-Dependent."
	//
	// なお、タイムアウトは「サーバーが CHANGE-REQUEST を黙って無視した」場合と
	// 「NAT がフィルタした」場合を区別できないため、CHANGE-REQUEST サポートの
	// 根拠にはならない。SupportsChangeRequest は、代替アドレスからの応答を
	// 実際に確認できた場合にのみ true とする
	result.FilteringType = AddressPortDependentFiltering
	return result, nil
}

// FullNATDetection はRFC 5780準拠の包括的なNAT判定を実行します
//
// RFC 5780: "This specification defines an experimental usage of the
//
//	Session Traversal Utilities for NAT (STUN) Protocol that
//	discovers the presence and current behavior of NATs and firewalls
//	between the STUN client and the STUN server."
//
// NATを2つの独立した動作で分類します（RFC 4787）：
//  1. Mapping Behavior: NATがどのように外部アドレス:ポートを割り当てるか
//  2. Filtering Behavior: NATがどのように外部からのパケットをフィルタリングするか
//
// この組み合わせにより、以下の9種類のNATタイプに分類されます：
//   - 3種類のマッピング × 3種類のフィルタリング = 9通り
//
// serverAddr は "host" または "host:port" 形式で指定します。
// マッピング・フィルタリングとも OTHER-ADDRESS/CHANGE-REQUEST を
// サポートする RFC 5780 対応サーバー（例: stunserver2025.stunprotocol.org）が必要です。
func FullNATDetection(serverAddr string) (*FullNATDetectionResult, error) {
	// Phase 1: マッピング判定
	// RFC 5780 Section 4.3: Determining NAT Mapping Behavior
	mappingResult, err := CheckMappingType(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("マッピング判定エラー: %w", err)
	}

	// Phase 2: フィルタリング判定
	// RFC 5780 Section 4.4: Determining NAT Filtering Behavior
	filteringResult, err := CheckFilteringBehavior(serverAddr)
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
