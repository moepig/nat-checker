# nat-checker

RFC 5780 準拠の NAT Mapping/Filtering 判定ライブラリ

## インストール

```bash
go get github.com/moepig/nat-checker
```

## 使い方

### 基本的な使用方法

```go
package main

import (
    "fmt"
    "log"

    checker "github.com/moepig/nat-checker"
)

func main() {
    // 包括的な NAT 判定を実行
    // RFC 5780 (OTHER-ADDRESS/CHANGE-REQUEST) 対応の STUN サーバーが必要
    result, err := checker.FullNATDetection("stunserver2025.stunprotocol.org")
    if err != nil {
        log.Fatalf("NAT検出エラー: %v", err)
    }

    // 結果を表示
    fmt.Printf("NAT Type: %s\n", result.DetailedType.LegacyName())
    fmt.Printf("Mapping: %s\n", result.MappingResult.NATType)
    fmt.Printf("Filtering: %s\n", result.FilteringResult.FilteringType)
}
```

サーバーは `host` または `host:port` 形式で指定できます。ポートを省略した場合は
STUN 標準ポート 3478 が使われます。

### マッピング動作のみを判定

```go
result, err := checker.CheckMappingType("stunserver2025.stunprotocol.org")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Mapping Type: %s\n", result.NATType)
```

### フィルタリング動作のみを判定

```go
result, err := checker.CheckFilteringBehavior("stunserver2025.stunprotocol.org")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Filtering Type: %s\n", result.FilteringType)
```

## NAT 分類

### レガシー NAT 分類

マッピングとフィルタリングの組み合わせによる分類：

| マッピング | フィルタリング | レガシー名 |
|-----------|--------------|----------|
| Endpoint Independent | Endpoint Independent | Full Cone NAT |
| Endpoint Independent | Address Dependent | Restricted Cone NAT |
| Endpoint Independent | Address+Port Dependent | Port Restricted Cone NAT |
| Address Dependent | Any | Symmetric NAT |
| Address+Port Dependent | Any | Symmetric NAT |

## API リファレンス

### FullNATDetection

```go
func FullNATDetection(serverAddr string) (*FullNATDetectionResult, error)
```

RFC 5780 準拠の包括的な NAT 判定を実行します。マッピングとフィルタリングの両方を判定します。

**パラメータ:**
- `serverAddr`: STUN サーバーのアドレス（`host` または `host:port` 形式）

**戻り値:**
- `FullNATDetectionResult`: 包括的な判定結果
- `error`: エラー情報

### CheckMappingType

```go
func CheckMappingType(serverAddr string) (*CheckMappingResult, error)
```

NAT マッピング動作のみを判定します (RFC 5780 Section 4.3)。

主アドレス宛（Test I）、代替 IP・主ポート宛（Test II）、代替 IP・代替ポート宛
（Test III）の外部マッピングを IP とポートの両方で比較して判定します。

**注意:** OTHER-ADDRESS 属性をサポートしていない STUN サーバーでは、
Address Dependent / Address and Port Dependent の区別ができないため
`Unknown` になります。

### CheckFilteringBehavior

```go
func CheckFilteringBehavior(serverAddr string) (*CheckFilteringResult, error)
```

NAT フィルタリング動作のみを判定します (RFC 5780 Section 4.4)。

**注意:** OTHER-ADDRESS・CHANGE-REQUEST 属性をサポートしていない STUN
サーバーでは、フィルタリング判定ができません。

## テスト

### ユニットテスト

```bash
go test -v
```

### 統合テスト

実際の STUN サーバーを使用したテスト：

```bash
INTEGRATION=1 go test -v
```
