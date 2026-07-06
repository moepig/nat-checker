// Example program demonstrating RFC 5780 compliant NAT detection
//
// This example shows how to use the FullNATDetection function to determine
// both mapping and filtering behavior of your NAT.
//
// Build and run:
//
//	go run ./example
package main

import (
	"fmt"
	"log"

	checker "github.com/moepig/nat-checker"
)

func main() {
	fmt.Println("=== RFC 5780 NAT Type Detection ===")
	fmt.Println()

	// Mapping/Filtering 判定には RFC 5780 (OTHER-ADDRESS/CHANGE-REQUEST)
	// 対応の STUN サーバーが必要。
	server := "stunserver2025.stunprotocol.org"

	result, err := checker.FullNATDetection(server)
	if err != nil {
		log.Fatalf("NAT検出エラー: %v", err)
	}

	fmt.Printf("NAT Type: %s\n", result.DetailedType.LegacyName())
	fmt.Printf("詳細分類: %s\n", result.DetailedType)
	fmt.Printf("Mapping: %s\n", result.MappingResult.NATType)
	fmt.Printf("Filtering: %s\n", result.FilteringResult.FilteringType)
}
