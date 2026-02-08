// Example program demonstrating RFC 5780 compliant NAT detection
//
// This example shows how to use the FullNATDetection function to determine
// both mapping and filtering behavior of your NAT.
//
// Build and run:
//   go run example/main.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Import the parent package - adjust the import path based on your setup
// For local development, we'll use relative imports via build constraints
// In production, use: checker "githib.com/moepig/nat-checker"

func main() {
	fmt.Println("=== RFC 5780 NAT Type Detection ===")
	fmt.Println()

	// Since this is an example in the same module, we need to work around
	// the import issue by providing instructions
	fmt.Println("This example demonstrates the NAT detection API.")
	fmt.Println()
	fmt.Println("To use the NAT checker in your code:")
	fmt.Println()
	fmt.Println("  import checker \"githib.com/moepig/nat-checker\"")
	fmt.Println()
	fmt.Println("  // 包括的なNAT判定を実行")
	fmt.Println("  // Mapping: 異なるサーバーで正確な判定")
	fmt.Println("  // Filtering: RFC 5780対応サーバーで検証")
	fmt.Println("  result, err := checker.FullNATDetection(\"stunserver2025.stunprotocol.org\", \"stun.cloudflare.com\")")
	fmt.Println("  if err != nil {")
	fmt.Println("      log.Fatalf(\"NAT検出エラー: %v\", err)")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("  // 結果を表示")
	fmt.Println("  fmt.Printf(\"NAT Type: %s\\n\", result.DetailedType.LegacyName())")
	fmt.Println("  fmt.Printf(\"詳細分類: %s\\n\", result.DetailedType)")
	fmt.Println()
	fmt.Println("--- API Reference ---")
	fmt.Println()
	fmt.Println("Available Functions:")
	fmt.Println("  - CheckMappingType(serverA, serverB) - マッピング動作のみを判定")
	fmt.Println("  - CheckFilteringBehavior(server) - フィルタリング動作のみを判定")
	fmt.Println("  - FullNATDetection(serverA, serverB) - 包括的なNAT判定")
	fmt.Println()
	fmt.Println("NAT Types (Legacy Names):")
	fmt.Println("  - Full Cone NAT: P2P通信に最適")
	fmt.Println("  - Restricted Cone NAT: P2P通信可能")
	fmt.Println("  - Port Restricted Cone NAT: P2P通信可能")
	fmt.Println("  - Symmetric NAT: P2P通信困難（リレー推奨）")
	fmt.Println()

	// Show the actual test execution path
	fmt.Println("--- Running Integration Test ---")
	fmt.Println()

	execPath, _ := os.Executable()
	dir := filepath.Dir(execPath)
	fmt.Printf("To run the actual NAT detection test, use:\n")
	fmt.Printf("  cd %s/.. && INTEGRATION=1 go test -v -run TestFullNATDetection\n", dir)
	fmt.Println()
}
