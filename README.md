# SSEFS

SSEFS は FUSE を利用したユーザ空間ファイルシステムです．

## 構成

- クライアント
  - Rust
  - FUSE (fuser)
- サーバ
  - Go
- 通信方式
  - HTTP

クライアントは FUSE を介して Linux のファイルシステムとして動作し，検索要求を HTTP 経由でサーバへ送信します．

---

## 動作環境

### クライアント

- Linux
- Rust
- Cargo
- FUSE

### サーバ

- Go

---

## クライアント側のビルド

プロジェクトディレクトリへ移動します．

```bash
cd ssefs
```

ビルドを実行します．

```bash
cargo build --release
```

---

## クライアント側の実行

マウントポイントを作成します．

```bash
mkdir -p mnt
```

実行します．

```bash
cargo run --release mnt
```

または

```bash
./target/release/ssefs mnt
```

---

## クライアント側とサーバ側の通信

現在の設定では，クライアントは以下のサーバへ HTTP リクエストを送信します．

- IPアドレス: `192.168.11.8`
- ポート番号: `2226`

例：

```text
http://192.168.11.8:2226/search?token=<token>
```

検索トークンを指定して検索結果を取得します．

---

## サーバ側の実行

プロジェクトディレクトリへ移動します．

```bash
cd server
```

実行します．

```bash
go run main.go
```

ビルドする場合：

```bash
go build
./server
```

---

## 動作確認

サーバが起動していることを確認します．

```bash
curl "http://192.168.11.8:2226/search?token=fruit"
```

正常に応答が返れば通信成功です．

クライアント起動後，マウントポイントへアクセスします．

```bash
ls mnt
```

```bash
ls mnt/fruit
```

---

## アンマウント

使用終了後はアンマウントします．

```bash
fusermount -u mnt
```