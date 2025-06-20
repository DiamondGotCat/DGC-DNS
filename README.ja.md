| [English](README.md) | 日本語 |

# DGC-DNS
実用的で軽量なオープンソースのDNSサーバー

## DGC-DNSについて
DGC-DNSは、Pythonで書かれた、実用的で軽量なDNSサーバーです。

## ドメイン処理システム
DGC-DNSには、以下の2つの名前解決システムがあります。
- ローカル解決: DGC-DNSに設定されたDNSレコードを使用して応答します。レコードがない場合、他の名前解決システムを使用してから、NXDOMAINを返します。
- パブリックDNSによる解決: 自動的にインターネットにあるDNSに要求することで、ローカル解決で回答不可能だったドメインもある程度解決できるようになります。
  - `main.py`内の`fallback_servers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]`の部分を変更することで、他のパブリックDNSも使用可能です。
  - パブリックDNSによる解決の場合、回答は自動的にキャッシュされ、次回からは同じリクエストにより高速に答えるようになっています。(`main.py`内の`@lru_cache(maxsize=1024)`を削除することで無効化できます。)

### ローカル解決に使用されるDNSレコードの保存場所
DNSレコードは全てスクリプトディレクトリの`records.json`に保存され、必要な時にロードされます。
後述するDGC-DNS APIを使用すれば、リモートからリロードや、レコードの追加/編集/削除などの様々な機能を利用可能です。

## DGC-DNS API
DGC-DNSの操作は、APIで行うことができます。

### セキュリティについて
デフォルトでは自身(`localhost`)からのリクエストに対してのみ回答します。
これは、外部からのAPIアクセスに対応しないための方法の一つです。
外部からも操作したい場合、`localhost`の方法をやめ、代わりにパスワードやAPIキーなどの方法を使用してください。

### 操作の種類
以下の操作をAPI経由で利用可能です。
- `GET /api/v1/status`: 動作しているかどうかを判定するためのエンドポイントです。正常な場合は`{"status": "ok", "content": "ok"}`が返ってきます。
- `GET /api/v1/reload`: `records.json`から再読み込みします。手動で編集した場合は、このエンドポイントを叩いてください。
- `GET /api/v1/records`: 現在読み込まれている`records.json`の中身を返します。
- `POST /api/v1/records/append`: DNSレコードを追加します。
- `POST /api/v1/records/remove`: DNSレコードを削除します。
- `POST /api/v1/records/edit`: DNSレコードを編集します。

## 利用事例
DGC-DNSは、開発者(DiamondGotCat)も使用しています。
- `ns1.diamondgotcat.net`, `ns2.diamondgotcat.net`: `35.208.247.170`への別ルート。
- `35.208.247.170`: 開発者のドメインを一括管理するDGC-DNSサーバー。

## ライセンス
このソフトウェアはMITライセンス下で提供されます。

---
Copyright (c) 2025 DiamondGotCat
