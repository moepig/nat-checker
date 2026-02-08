# nat-checker

RFC 5780 準拠の NAT Mapping/Filtering 判定ライブラリ

## インストール

```bash
go get githib.com/moepig/nat-checker
```

## 使い方

### 基本的な使用方法

```go
package main

import (
    "fmt"
    "log"

    checker "githib.com/moepig/nat-checker"
)

func main() {
    // 包括的な NAT 判定を実行
    result, err := checker.FullNATDetection(
        "stun.cloudflare.com",
        "stun1.l.google.com",
    )
    if err != nil {
        log.Fatalf("NAT検出エラー: %v", err)
    }

    // 結果を表示
    fmt.Printf("NAT Type: %s\n", result.DetailedType.LegacyName())
    fmt.Printf("Mapping: %s\n", result.MappingResult.NATType)
    fmt.Printf("Filtering: %s\n", result.FilteringResult.FilteringType)
}
```

### マッピング動作のみを判定

```go
result, err := checker.CheckMappingType(
    "stun.cloudflare.com",
    "stun1.l.google.com",
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Mapping Type: %s\n", result.NATType)
```

### フィルタリング動作のみを判定

```go
result, err := checker.CheckFilteringBehavior("stun.cloudflare.com")
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
func FullNATDetection(serverIpA, serverIpB string) (*FullNATDetectionResult, error)
```

RFC 5780 準拠の包括的な NAT 判定を実行します。マッピングとフィルタリングの両方を判定します。

**パラメータ:**
- `serverIpA`: 最初の STUN サーバーの IP アドレスまたはホスト名
- `serverIpB`: 2 番目の STUN サーバーの IP アドレスまたはホスト名

**戻り値:**
- `FullNATDetectionResult`: 包括的な判定結果
- `error`: エラー情報

### CheckMappingType

```go
func CheckMappingType(serverIpA, serverIpB string) (*CheckMappingResult, error)
```

NAT マッピング動作のみを判定します。

### CheckFilteringBehavior

```go
func CheckFilteringBehavior(serverAddr string) (*CheckFilteringResult, error)
```

NAT フィルタリング動作のみを判定します。

**注意:** CHANGE-REQUEST 属性をサポートしていない STUN サーバーでは、フィルタリング判定ができません。

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
