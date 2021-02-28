# slabot
Bringing true chatops with slack to your team.

![1](https://user-images.githubusercontent.com/22161385/109412353-d521c380-79ea-11eb-88d5-a83380923002.gif)

## 提案

slackでDevもOpsも集まってリモワ仕事してるとこういう事ないですか？

「なんか、このログ気になりますね。。/var/xxxでこのエラーコードでgrepしてもらえますか？」

えっちらおっちら　※ログイン→コマンド叩く→必要個所切り出す→slackに貼る

「すみません、エラーコード間違ってました！正しくはxxです」

えっちらおっちら

「切り出した期間が狭いんで、出てくるの全部貼ってもらえますか？」

えっちらおっちら

「度々すみません、さっき再発したので同じのもう一回調べてもらえますか？」


**ぴええええええええん**ってなって上司に相談すると

「開発にログイン権限渡したくなくて、、面倒だけどゴメンね」

～END～

### というのをUXを解消してくれるのが、このツール！

先日作った[slackの操作をシェルプロっぽくするツール。あとショートカットで文字送ったり](https://github.com/yasutakatou/slackops)と組み合わせると効果絶大です！（たぶん）

## 動かし方

```
git clone https://github.com/yasutakatou/slabot
cd slabot
go build slabot.go
```

バイナリをダウンロードして即使いたいなら[こっち](https://github.com/yasutakatou/slabot/releases)

### 注！ SlackにBotを許可する設定を入れる必要があります

[この辺りを参考に設定していただければ](https://qiita.com/frozenbonito/items/cf75dadce12ef9a048e9)
トークンの環境変数の設定や、/slack/eventsに飛ばすところなんか同じです。

## 使い方

要するに踏み台の機能がBotになったと思っていただければ。全てBotヘメンションしてください

1. SETHOST=[コンフィグの定義名]でアクセス先を指定します
2. ユーザーIDが許可されていれば、アクセス先が設定できます
3. CLIのコマンドを入れると、ローカルにテンポラリのシェルが書かれます
4. scpで転送し、転送先のサーバーでシェルが実行されます

なお、cdコマンドに対応しているので**cdでディレクトリを移動したら保持**されます。

## コンフィグファイル

使うのにコンフィグファイルに動作を定義します。サンプルを参考にカスタマイズしてください。

- [ALLOWID]
	- Botの使用を許可するSlackのメンバーIDを指定します。[この辺りを参考](https://help.receptionist.jp/?p=1100)に確認してください
		- U01NJBRKGLD
- [PERMIT]
	- 実行を許可するコマンドを列記します、がまだ**未実装です！**
- [HOSTS]
	- 接続するホスト情報を定義します。以下のようにカンマ区切りで定義します。
	- 定義名,IP/名前解決できるホスト名,SSHのポート番号,ユーザー名,パスワード,使用するシェルのパス
	- test,127.0.0.1,22,slabot,secretpassword,/bin/bash

### コンフィグ記載例

```
[ALLOWID]
U01NJBRKGLD
[PERMIT]
ls
cat
cd
[HOSTS]
test,127.0.0.1,22,slabot,secretpassword,/bin/bash
```

## 起動オプション

実行ファイルは以下、起動オプションがあります。

```
Usage of slabot.exe:
  -api
        [-api=api mode (true is enable)]
  -cert string
        [-cert=ssl_certificate file path (if you don't use https, haven't to use this option)] (default "localhost.pem")
  -config string
        [-config=config file)] (default ".slabot")
  -debug
        [-debug=debug mode (true is enable)]
  -key string
        [-key=ssl_certificate_key file path (if you don't use https, haven't to use this option)] (default "localhost-key.pem")
  -port string
        [-port=port number] (default "8080")
  -retry int
        [-retry=retry counts.] (default 10)
  -scp
        [-scp=need scp mode (true is enable)] (default true)

```
### -api
slackのボットじゃなくてrest apiサーバーを起動します。以下みたいにapiを投げられます。

```
curl -k -H "Content-type: application/json" -X POST https://127.0.0.1:8080/api -d '{"user":"C01N6M21555","command":"SETHOST=test"}'
curl -k -H "Content-type: application/json" -X POST https://127.0.0.1:8080/api -d '{"user":"C01N6M21555","command":"pwd"}'
```

### -cert
apiモードの時に指定する公開鍵ファイルです。

### -config
読み込むコンフィグファイルを指定します。デフォルトは実行ファイルのカレントにある **.slabot** です。

### -debug
デバッグモードで起動します。指定すると内部動作情報が色々出てきます。

### -key
apiモードの時に指定する秘密鍵ファイルです。

### -port
動作するポート番号です。この設定はslack/apiモード両方で有効になります。

### -retry
内部でscp、sshをリトライする回数です。失敗時にリトライします。

### -scp
scpでシェルを転送しないモードです。コマンドのみ流すので**応答スピードが倍**になります<br>
が、使えるコマンドに**反面ダブルクォーテーション(")が使えなくなります**

## これから実装するつもりのやつ

- 動かして良いコマンドの判定処理
- 使っちゃいけない文字のバリデーションチェック
- 指定したファイルをslackにアップロードする
- 指定したフォルダ配下を.tar.gz辺りで固めてslackにアップロードする
- 20行とか超える長い行数の出力を畳んだりしてslackにアップロードする
- エラーをslack側に分かりやすく通知する
- viとかターミナルもってくやつどうするか・・？
- パスワードアクセスだけじゃなくて鍵認証にも対応する

## ライセンス

BSD-2-Clause License, ISC License

