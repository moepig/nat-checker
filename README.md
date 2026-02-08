# NAT Checker - RFC 5780準拠 NAT判定ライブラリ

Go言語で実装されたRFC 5780準拠のNAT（Network Address Translation）判定ライブラリです。STUNプロトコルを使用して、NATのマッピング動作とフィルタリング動作を判定します。

## 特徴

- ✅ RFC 5780準拠の包括的なNAT判定
- ✅ マッピング動作の判定（3種類）
- ✅ フィルタリング動作の判定（3種類）
- ✅ レガシーNAT分類名のサポート（Full Cone, Symmetric等）
- ✅ 複数のSTUNサーバーサポート
- ✅ エラーハンドリングとフォールバック戦略
- ✅ 包括的なテストスイート

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
    // 包括的なNAT判定を実行
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

## NAT分類

### マッピング動作（Mapping Behavior）

NATが外部アドレス:ポートをどのように割り当てるかを示します：

- **Endpoint Independent Mapping**: 宛先に関係なく同じマッピングを使用
- **Address Dependent Mapping**: 宛先IPアドレスによってマッピングが変わる
- **Address and Port Dependent Mapping**: 宛先IP:ポートによってマッピングが変わる

### フィルタリング動作（Filtering Behavior）

NATが外部からのパケットをどのようにフィルタリングするかを示します：

- **Endpoint Independent Filtering**: すべての着信パケットを許可
- **Address Dependent Filtering**: 通信済みIPアドレスからの着信のみ許可
- **Address and Port Dependent Filtering**: 通信済みIP:ポートからの着信のみ許可

### レガシーNAT分類

マッピングとフィルタリングの組み合わせによる分類：

| マッピング | フィルタリング | レガシー名 | P2P適性 |
|-----------|--------------|----------|---------|
| Endpoint Independent | Endpoint Independent | Full Cone NAT | ✓ 最適 |
| Endpoint Independent | Address Dependent | Restricted Cone NAT | ✓ 良好 |
| Endpoint Independent | Address+Port Dependent | Port Restricted Cone NAT | ○ 可能 |
| Address Dependent | Any | Symmetric NAT | ✗ 困難 |
| Address+Port Dependent | Any | Symmetric NAT | ✗ 困難 |

## API リファレンス

### FullNATDetection

```go
func FullNATDetection(serverIpA, serverIpB string) (*FullNATDetectionResult, error)
```

RFC 5780準拠の包括的なNAT判定を実行します。マッピングとフィルタリングの両方を判定します。

**パラメータ:**
- `serverIpA`: 最初のSTUNサーバーのIPアドレスまたはホスト名
- `serverIpB`: 2番目のSTUNサーバーのIPアドレスまたはホスト名

**戻り値:**
- `FullNATDetectionResult`: 包括的な判定結果
- `error`: エラー情報

### CheckMappingType

```go
func CheckMappingType(serverIpA, serverIpB string) (*CheckMappingResult, error)
```

NATマッピング動作のみを判定します。

### CheckFilteringBehavior

```go
func CheckFilteringBehavior(serverAddr string) (*CheckFilteringResult, error)
```

NATフィルタリング動作のみを判定します。

**注意:** CHANGE-REQUEST属性をサポートしていないSTUNサーバーでは、フィルタリング判定ができません。

## テスト

### ユニットテスト

```bash
go test -v
```

### 統合テスト

実際のSTUNサーバーを使用したテスト：

```bash
INTEGRATION=1 go test -v
```

特定のテストのみ実行：

```bash
INTEGRATION=1 go test -v -run TestFullNATDetection
```

## 対応STUNサーバー

以下のSTUNサーバーで動作確認済み：

- `stun.cloudflare.com`
- `stun1.l.google.com`
- `stun.ekiga.net`

**注意:** 多くのSTUNサーバーはCHANGE-REQUEST属性（RFC 3489）をサポートしていません。フィルタリング判定にはこの属性が必要です。

## 技術仕様

### サポートするRFC

- RFC 5780: NAT Behavior Discovery Using STUN
- RFC 8489: Session Traversal Utilities for NAT (STUN)
- RFC 3489: STUN (classic) - CHANGE-REQUEST属性のみ

### STUNメッセージタイプ

- Binding Request (0x0001)
- Binding Success Response (0x0101)
- Binding Error Response (0x0111)

### STUNアトリビュート

- MAPPED-ADDRESS (0x0001)
- CHANGE-REQUEST (0x0003)
- CHANGED-ADDRESS (0x0005)
- XOR-MAPPED-ADDRESS (0x0020)
- ERROR-CODE (0x0009)
- OTHER-ADDRESS (0x802C)
