# P4 + SFC による動的トラフィック制御

BMv2 (`simple_switch_grpc`) 上の P4 スイッチと SFC サーバを組み合わせ、送信元ごとのトラフィック量に応じて **ロードバランス → レート制限 → 破棄** の順に防御レベルを自動で切り替える実験環境です。

> このREADMEは、リポジトリ内のコードから読み取れる内容をもとに書いています。「(推測)」と付けた箇所は、コードから断定できなかった部分です。

## 全体の動き

```
 h1,h2 ──► s1 ──► s2 ──► h4 (CDN_4)
            │  └─► s3 ──► h5 (CDN_5)
            │        └──► s4 ──► h6 (宛先サーバ)
            └─► h3 (SFCサーバ)
```

1. **カウント**: s1 が IPv4 パケットごとに送信元 IP の CRC32 から `index` (0〜1023) を求め、レジスタ `packet_counter[index]` を加算します。
2. **検知**: `monitor_mbps.py` が 1 秒ごとにレジスタを読み、増加量から Mbps を概算します。上側の閾値を超えた index を「怪しい」と判定します。
3. **リダイレクト**: `runtime_test.py` が P4Runtime で `redirect_table` にエントリを入れ、該当送信元のパケットを h3 (SFC サーバ) へ転送します。同時にその index の meter も設定します。
4. **SFC 判定**: SFC サーバが送信元ごとのトラフィックを見てレベル (1〜3) を決め、IP ヘッダ下位 2bit (`packet_level`、TOS/ECN 領域) に書き込んで s1 へ送り返します。
5. **処理**: s1 は `packet_level` に応じて処理します。

| `packet_level` | 意味 | s1 での処理 |
|---|---|---|
| 0 | 未処理 | `redirect_table` にヒットすれば h3 へ転送、しなければ通常転送 |
| 1 | Load Balance | 宛先を `10.0.4.4` / `10.0.5.5` に振り分け (index の偶奇で決定) |
| 2 | Rate Limit | meter が RED なら破棄、それ以外は LB と同じ宛先書き換え |
| 3 | Drop | 破棄 |

6. **解除**: 検知側の Mbps が下側の閾値を下回ると、`runtime_test.py <index> 0` でリダイレクトルールを削除します。上側 8 Mbps / 下側 6 Mbps のヒステリシスで、状態がばたつかないようにしています。

## トポロジ (`topology.json`)

| ホスト | IP | 役割 |
|---|---|---|
| h1 | 10.0.1.1 | クライアント / 攻撃トラフィック送信元 (推測) |
| h2 | 10.0.2.2 | クライアント。`monitor_mbps.py` の監視対象外 (比較用の正常ホストと思われる。推測) |
| h3 | 10.0.3.3 | **SFC サーバ** |
| h4 | 10.0.4.4 | LB 先 (CDN_4) |
| h5 | 10.0.5.5 | LB 先 (CDN_5) |
| h6 | 10.0.6.6 | 宛先サーバ (iperf サーバ / ping 対象) |

スイッチ: s1 (P4 で制御する本体)、s2〜s4 (単純な IPv4 転送のみ)。リンクは `s1-s2`, `s1-s3`, `s1-s4`, `s2-s4`, `s3-s4` です。

## ファイル構成

### P4 / 構成
| ファイル | 内容 |
|---|---|
| `basic.p4` | データプレーン本体。ハッシュ計算、パケットカウンタ、meter、`redirect_table`、`ipv4_lpm`、`packet_level` 別の処理 |
| `topology.json` | Mininet トポロジ |
| `s1-runtime.json` 〜 `s4-runtime.json` | 各スイッチの初期テーブル。s1 には `count_table` に h1/h2/h3 が登録済み |
| `Makefile` | p4lang/tutorials の `../../utils/Makefile` を読み込む。`make run` でビルドと Mininet 起動 |

### 制御プレーン
| ファイル | 内容 |
|---|---|
| `monitor_mbps.py` | **現行の監視プログラム**。レジスタから Mbps を概算し、ヒステリシス付きでルールを追加・削除 |
| `runtime_test.py` | **現行のルール操作**。`<index> <level>` を受け取り、`redirect_table` の追加/変更/削除と meter 設定を行う。`level=0` で削除 |
| `sniffer_test.py` | **現行のスニファ**。s1 の各インタフェースを監視し、`index,src,dst` を `./tmp/hosts_test.txt` に記録 (index は送信元 IP のみのハッシュ) |
| `meter.py` | 全 index に meter (CIR=5, PIR=6 packets/s) を一括設定するスクリプト。現在の運用では `runtime_test.py` が meter を設定するため、単独実験用と思われる (推測) |

### SFC サーバ (h3 で実行)
| ファイル | 内容 |
|---|---|
| `SFCserver.py` | Scapy 版。5 秒窓のパケット数で判定 (LB≥0, RL≥2, DROP≥60) |
| `SFCserver_test.py` | Raw socket 版。1 秒窓の Mbps で判定し、送信元を h3 に書き換える (SNAT) |
| `SFCserver_test_.py` | `SFCserver_test.py` の別設定版 (RL/DROP 閾値 20 Mbps)。どれを評価に使ったかはコードからは不明 |

### トラフィック生成・測定
| ファイル | 内容 |
|---|---|
| `send.py` / `receive.py` | 1 パケット送信 / TCP 受信表示 (p4lang/tutorials 由来) |
| `send_fast.py` | TCP パケットを指定 pps で送り続ける |
| `send_fast_udp.py` | Raw socket で UDP を指定 pps・時間で送信 (高帯域用) |
| `receive_test.py` | TCP 受信時に IP/TOS/ペイロードを詳細表示 |
| `measure_send.py` / `measure_recv.py` | 送信時刻入りの UDP (ポート 5555) を送り、遅延・ジッタ・ロス率を CSV に追記 |
| `h1_throughput`, `h2_throughput` | `iperf` を繰り返し実行し、平均・標準偏差・95% 信頼区間を表示 |
| `rtt` | `ping` で RTT を測定して CSV 化 |
| `packet_loss` | `ping` でパケットロス率を測定して CSV 化 |
| `perf` | `iperf -c 10.0.6.6 -t 10 -i 1` の 1 行スクリプト |
| `del` | `tmp/hosts.txt` を削除 (パスが `/home/p4/tutorials/exercises/count/` に固定) |

### 結果データ
`result/`, `result_h1/`, `result_h2/`, `latency/` および直下の `*.csv` に実験結果が入っています。

### 旧版と思われるファイル
- `monitor.py` / `monitor_test.py` / `runtime.py` / `sniffer.py` / `receive.py` は旧版の可能性が高いです。
  - `monitor.py` と `monitor_test.py` はレジスタ名に `MyIngress.test_counter` を使っていますが、現在の `basic.p4` には存在せず、`packet_counter` です。そのままでは動きません。
  - `sniffer.py` は送信元+宛先でハッシュしますが、現在の `basic.p4` は送信元のみです。index が一致しないため使えません。
  - `runtime.py` は `runtime_test.py` と内容が同一です (ただし `monitor_mbps.py` は `runtime_test.py` を呼びます)。

## 実行手順

p4lang/tutorials の演習ディレクトリ (`exercises/<名前>/`) に置いて実行する前提です。`Makefile` が `../../utils/Makefile` を読み込み、`runtime_test.py` が `../../utils/` の `p4runtime_lib` を使うためです。単体のクローンでは動きません。

動作環境: p4lang/tutorials の VM (BMv2、p4c、Mininet、Scapy、P4Runtime ライブラリ入り)。

```bash
# 1. ビルドして Mininet 起動 (build/ pcaps/ logs/ が作られる)
make run
# 終了後は make stop / make clean
```

Mininet 起動後、それぞれ別ターミナルで次を実行します。

```bash
# s1 側 (ホスト OS 側)
python3 sniffer_test.py          # index と (src,dst) の対応を ./tmp/hosts_test.txt に記録
python3 monitor_mbps.py          # 監視。閾値超過で runtime_test.py を自動実行

# Mininet の xterm 等で h3 上
python3 SFCserver_test.py        # または SFCserver.py

# h6 上
iperf -s

# h1 / h2 上
./h2_throughput                  # 正常側のスループット測定
python3 send_fast_udp.py 10.0.6.6 1250 10   # 例: 1250 pps を 10 秒 (約 15 Mbps)
```

`monitor_mbps.py` はルールを入れる際に `hosts_test.txt` を参照するため、**先に `sniffer_test.py` で対象の通信を一度流して index を登録しておく必要があります**。

## 注意点・既知の不整合

- **パケットサイズの前提**: `monitor_mbps.py` は `AVG_PKT_BYTES = 1500` でパケット数から Mbps を概算しています。コミットメッセージには「攻撃パケットサイズ1000想定」とありますが、コードは 1500 のままです。実際のサイズが違えば Mbps は比例してずれます。
- **ハッシュ衝突**: index は 1024 個にハッシュしているため、別の送信元が同じ index に衝突する可能性があります。
- **閾値は用途に合わせた値**: 検知 8/6 Mbps、SFC 側の閾値 (パケット数や Mbps) はファイルごとに異なります。実験条件に合わせて調整してください。
- **meter の設定**: `runtime_test.py` は `METER_RATE = 1` (コメントアウトされた旧値は 660) で、全 index ではなく対象 index にのみ設定します。
- **`del` スクリプト**はパスが固定されているため、環境が違えば修正が必要です。
- ライセンス表記があるのは `send.py` / `receive.py` など p4lang/tutorials 由来のファイルのみで、リポジトリ全体のライセンスは未設定です。

## 参考

- [p4lang/tutorials](https://github.com/p4lang/tutorials): ベースとなる演習環境 (`utils/Makefile`, `run_exercise.py`, `p4runtime_lib`)
