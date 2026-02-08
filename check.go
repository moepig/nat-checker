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
