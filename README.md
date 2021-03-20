# slabot

Bringing true chatops with slack to your team.

![2](https://user-images.githubusercontent.com/22161385/110207729-d0687e00-7ec8-11eb-8a82-d9bb248f92ed.gif)

slack will be reborn as a shell prompt.<br>
Let's get devs and SREs together in the same channel, and work with the same authority!

- v0.2<br>
	- パスワード文字列の暗号化<br>
		- 平文でパスワードを書いてたのを暗号化文字列にできるようにしました（気休め的な）	
	- 禁止文字列の実装<br>
		- rm -rf /みたいな危険コマンドの実行を弾けるようにしました（ただし、やっつけ実装）
	- ファイルのアップロード<br>
		- ファイルをslackにアップロードできるようにしました
	- 長い出力をファイルにまとめる実装<br>
		- 長い出力をだらだらslackに載せずに、テキストファイルにまとめるようにしました
	- エラーをちゃんとslackに出す<br>
		- v0.1はローカルだけの出力が多かったので修正しました
	- 鍵認証に対応<br>
		- 鍵認証ファイルを指定した場合に、自動的に鍵認証するようにしました

- v0.3<br>
	- Windows対応(クライアント／ボット両方)<br>
		- Windowsバイナリに対応と、あわせてコマンド投げ込み先をWindows対応にしました
	- ソケットモード対応<br>
		- これでngrokとかでインバウント通信を開けなくて良くなりました。
	- コンフィグファイルの変更を検知してホットリロード<br>
		- コンフィグファイルに変更があった場合に自動的に再読み込みします
	- 実行者の名前を出力する<br>
		- 実行者が多数いると埋もれてしまうので、命令した人にメンション入れるようにしました
	- aliasコマンドをつける<br>
		- 長ったらしいコマンドを短縮登録できるようにしました
	- ログ出力をつける<br>
		- systemdに登録した時にログが残しずらいのでログ出力モードをつけました 

## 解決したい課題

### slackでDevもOpsも集まってリモワ仕事してるとこういう事ないですか？

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

先日作った[slackの操作をシェルプロっぽくするツール。あとショートカットで文字送ったり](https://github.com/yasutakatou/slackops)<br>
と組み合わせると効果絶大です！（たぶん）

## 動かし方

```
git clone https://github.com/yasutakatou/slabot
cd slabot
go build slabot.go
```

バイナリをダウンロードして即使いたいなら[こっち](https://github.com/yasutakatou/slabot/releases)

### 注！ SlackにSocketModeでBotを許可する設定を入れる必要があります(v0.3より)

[この辺りを参考に設定していただければ](https://www.klab.com/jp/blog/tech/2021/0201-slack.html)<br>
トークンの環境変数の設定は同じです。以下ソケットモードの設定が必要です。

![socketmode](https://user-images.githubusercontent.com/22161385/111068211-3a0d0b80-850b-11eb-85b8-79744b081145.png)
![socktoken](https://user-images.githubusercontent.com/22161385/111068221-4002ec80-850b-11eb-9037-bb92495fd0b9.png)


### 注！ SlackにBotを許可する設定を入れる必要があります　(v0.2までのslack/eventsでインバウントでイベントを待ち受ける場合)

[この辺りを参考に設定していただければ](https://qiita.com/frozenbonito/items/cf75dadce12ef9a048e9)<br>
トークンの環境変数の設定や、/slack/eventsに飛ばすところなんか同じです。以下スコープが必要です。

![hooktoken](https://user-images.githubusercontent.com/22161385/111068222-41ccb000-850b-11eb-9d64-dc91d11adce2.png)
![scopes](https://user-images.githubusercontent.com/22161385/110207744-eaa25c00-7ec8-11eb-8cb2-f93e5e7fab5e.png)

## 使い方

要するに踏み台の機能がBotになったと思っていただければ。全てBotヘメンションしてください

1. SETHOST=[コンフィグの定義名]でアクセス先を指定します

![sethost](https://user-images.githubusercontent.com/22161385/110207738-de1e0380-7ec8-11eb-96d7-f2fbb118cccd.png)

2. ユーザーIDが許可されていれば、アクセス先が設定できます
3. CLIのコマンドを入れると、ローカルにテンポラリのシェルが書かれます
4. scpで転送し、転送先のサーバーでシェルが実行されます
	- ながったらしい出力はテキストファイルとしてアップロードされ、畳まれて表示されます。
	
![long](https://user-images.githubusercontent.com/22161385/110207746-ed04b600-7ec8-11eb-8f24-ce2302187f0a.png)

なお、cdコマンドに対応しているので**cdでディレクトリを移動したら保持**されます。

- v0.3より 実行者のお名前をメンションしてくれるようになりました！

![viewname](https://user-images.githubusercontent.com/22161385/111068224-45f8cd80-850b-11eb-9240-b9bf3901b423.png)

### その他の使い方

- UPLOAD=(ファイル名)でサーバー上のファイルをアップできます。

![upload](https://user-images.githubusercontent.com/22161385/110207740-e4ac7b00-7ec8-11eb-8358-5133b984ec3d.png)

- alias で長ったらしいコマンドの短縮名を付ける事ができます。

alias (**短縮名**)=(**長ったらしいコマンド**)で登録できます。aliasのみなら登録されている一覧を出します。

![alias1](https://user-images.githubusercontent.com/22161385/111068228-485b2780-850b-11eb-8c7d-0b808352882a.png)

alias (**短縮名**)= ←空 でaliasを解除できます。

![alias2](https://user-images.githubusercontent.com/22161385/111068233-4a24eb00-850b-11eb-934b-d385eba8e51d.png)

## コンフィグファイル

使うのにコンフィグファイルに動作を定義します。サンプルを参考にカスタマイズしてください。

#### v0.3より コンフィグファイルのホットリロードに対応しました。つまり、ファイルの変更を検知して自動で再読み込みします。

- [ALLOWID]
	- Botの使用を許可するSlackのメンバーIDを指定します。[この辺りを参考](https://help.receptionist.jp/?p=1100)に確認してください
		- U01NJBRKGLD
- [REJECT]
	- 実行を許可しないコマンド等の文字列を列記します。以下のように**文字列が入ってたら**弾きます。

![reject](https://user-images.githubusercontent.com/22161385/110207742-e8400200-7ec8-11eb-83ed-46777efac839.png)

メモ: どこに入ってても無条件で弾きます。 \`\` を使う場合や、ls ;　　　rm -rfみたいにシェルで表現できる事が多いのでうまくバリデーションできないからです

- [HOSTS]
	- 接続するホスト情報を定義します。以下のようにカンマ区切りで定義します。
	- 定義名,IP/名前解決できるホスト名,SSHのポート番号,ユーザー名,※認証情報,使用するシェルのパス
	- test,127.0.0.1,22,slabot,secretpassword,/bin/bash
	- この**定義名**を**SETHOST**の後に書くことでコマンドの投げ先をスイッチさせます

※認証情報　**平文のパスワード**、**暗号化されたパスワード文字列**、**認証鍵のファイル**の3つのどれかを指定します

- v0.3より WindowsのSSH Serverに対応しました！

以下のようにWindowsのOpenSSHにコマンドを投げ込めるようにしました。

![wintarget](https://user-images.githubusercontent.com/22161385/111068235-4db87200-850b-11eb-87c2-c88ddee7d320.png)

使用するシェルのパス(SHEBANG)に以下のようにcmd /Cを指定する事で対応できます。/Cが大文字なので注意！

![winshebang](https://user-images.githubusercontent.com/22161385/111068236-4f823580-850b-11eb-9bda-3e63fe38471c.png)

### コンフィグ記載例

```
[ALLOWID]
U01NJBRKGLD
[REJECT]
rm 
passwd
vi 
[HOSTS]
test,127.0.0.1,22,ec2-user,/home/ec2-user/test.pem,/bin/bash
```

## 起動オプション

実行ファイルは以下、起動オプションがあります。

```
Usage of slabot:
  -api
        [-api=api mode (true is enable)]
  -bot string
        [-bot=slack bot name (@ + name)] (default "slabot")
  -cert string
        [-cert=ssl_certificate file path (if you don't use https, haven't to use this option)] (default "localhost.pem")
  -config string
        [-config=config file)] (default ".slabot")
  -debug
        [-debug=debug mode (true is enable)]
  -decrypt string
        [-decrypt=password decrypt key string]
  -encrypt string
        [-encrypt=password encrypt key string ex) pass:key (JUST ENCRYPT EXIT!)]
  -key string
        [-key=ssl_certificate_key file path (if you don't use https, haven't to use this option)] (default "localhost-key.pem")
  -log
        [-log=logging mode (true is enable)]
  -plainpassword
        [-plainpassword=use plain text password (true is enable)]
  -port string
        [-port=port number] (default "8080")
  -rest
        [-rest=normal slack mode (true is enable)]
  -retry int
        [-retry=retry counts.] (default 10)
  -scp
        [-scp=need scp mode (true is enable)] (default true)
  -toFile int
        [-toFile=if output over this value. be file.] (default 20)
```

### -api
slackのボットじゃなくてrest apiサーバーを起動します。以下みたいにapiを投げられます。デフォルトはfalseです。

```
curl -k -H "Content-type: application/json" -X POST https://127.0.0.1:8080/api -d '{"user":"C01N6M21555","command":"SETHOST=test"}'
curl -k -H "Content-type: application/json" -X POST https://127.0.0.1:8080/api -d '{"user":"C01N6M21555","command":"pwd"}'
```

### -bot
botの名前です。slackから呼び出すときの名前を指定します。デフォルトは**slabot**で、slackから @slabot で呼びます。

### -cert
apiモードの時に指定する公開鍵ファイルです。

### -config
読み込むコンフィグファイルを指定します。デフォルトは実行ファイルのカレントにある **.slabot** です。

### -debug
デバッグモードで起動します。指定すると内部動作情報が色々出てきます。

### -decrypt
コンフィグに**暗号化されたパスワード文字列**を使う場合に、**複合するためのキー**を指定します。

### -encrypt
コンフィグに**暗号化されたパスワード文字列**を使う場合に、**パスワード**と**複合するためのキー**を指定して暗号文字を生成します。<br>
出力した文字列をコンフィグの認証情報部分に張り付けてください。

```
$ slabot.exe -encrypt=mypassword:decryptkey
Encrypt: 5NVkTdvu5-g0pQCcy0RpOnxuaLFplSJZ0SIjtQqyVZKMGcFIuiY=
```

このオプションを指定した場合は、暗号文字生成後に実行終了します。(既に動いているプロセスには影響はない)

### -key
apiモードの時に指定する秘密鍵ファイルです。

### -log
ログ出力モードです。デバッグログが以下のように年・月・日・時のフォーマットで出力されます。

![logging](https://user-images.githubusercontent.com/22161385/111068741-61fd6e80-850d-11eb-8c4a-c890453bc251.png)

### -plainpassword
パスワード平文モードです。trueにすると、コンフィグの認証情報部分の文字列を複合せずに平文のまま認証します。

### -port
動作するポート番号です。この設定はslack/apiモード両方で有効になります。

### -rest
v0.2までのslack/eventsでインバウントでイベントを受け取るモードです。デフォはfalseです。

### -retry
内部でscp、sshをリトライする回数です。失敗時にリトライします。

### -scp
scpでシェルを転送しないモードです。コマンドのみ流すので**応答スピードが倍**になります<br>
が反面、使えるコマンドに**ダブルクォーテーション(")が使えなくなります**<br>
@slabot echo "t e s t" > sample みたいなのが出来なくなるってことっすね。

### -toFile
長い行数の出力をテキストファイルにして、アップロードする際の閾値になります。デフォルトは**20**で20行を越える場合にファイルに変換されます。

## やっていき

-設定をエクスポートして永続化
-もっとセキュリティ的につよく
-アップロードに対応
-ホスト選択のインタラクティブメッセージ化
-アイコンとか選べるように

## ライセンス

BSD-2-Clause License, ISC License, BSD-3-Clause License,

