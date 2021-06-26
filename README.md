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

- v0.4<br>
	- 設定をエクスポートして永続化<br>
		- アクセス先やディレクトリ、alias定義を変更時にコンフィグに書き出すようにしました
	- もっとセキュリティ的につよく<br>
		- 禁止コマンドを実行したときに、アラートとしてメンションを飛ばすようにしました
	- アップロードに対応<br>
		- 直前にslackにあげたファイルをサーバー側にアップロードできるようにしました
	- ホスト選択のインタラクティブメッセージ化<br>
		- アクセス先の切り替えを分かりやすく、インタラクティブ化しました
	- ホスト定義の自動チェックモード追加<br>
		- コンフィグ読み込み時にホスト定義がアクセス可能かどうかチェックするようにしました

- v0.5<br>
	- マルチタスクに対応<br>
		- 重いタスク実行時に完了かタイムアウトまで次のコマンドが実行できなかったので平行できるようにしました
	- リモートサーバーからのファイルアップに対応<br>
		- コードを実行したサーバー上からファイルがアップできなかったのでリモートサーバーからバケツリレーするようにしました
	- (無くなった機能)REST APIと旧来のBot機能を廃止し、socketmode一本に統一しました
		- 開発時も使ってないのでメンテする意味も無いかなって

- v0.6<br>
	- 設定をラベル化して各ユーザーに細かいロールを付けれるようにしました
		- アラートエスカレーション先のラベル化
		- 使用許可するIDに使用不可コマンド、ファイルのダウンロード／アップロードの権限付与
		- 使用禁止コマンドのラベル化
		- アクセス可能ホストのラベル化

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

# セットアップの仕方

このツールはslack側の実行許可が必要です。以下の設定をしてください

1. ツールをBotとして登録します
- goto [slack api](https://api.slack.com/apps)
- Create New(an) App
	- define (Name)
	- select (Workspce)
	- Create App
- App-Level Tokens
	-Generate Token and Scopes
	- define (Name)
	- Add Scope
		- connections:write
	- Generate
		- 後で使うのでxapp-から始まるトークンを控えてください
	- Done
- Socket Mode
	- Enable Socket Mode
		- On
- OAuth & Permissions
	- Scopes
	- Bot Token Scopes
		- app_mentions:read
		- channels:history
		- chat:write
		- files:read
		- files:write
		- users:read
	- Install to Workspace
	- Bot User OAuth Token
		- 後で使うのでxoxb-から始まるトークンを控えてください
- Event Subscriptions
	- Enable Events
		- On
	- Subscribe to bot events
	- Add Bot User Event
		- app_mentions:read
		- channels:history
	- Save Changes

2. Slackのアプリからボットを使いたいチャンネルで招待してください
	- invite bot
		- @(ボットの名前)
	- invite

3. ターミナルからトークンの設定とツールを実行します
	- set environment
		- windows
			- set SLACK_APP_TOKEN=xapp-...
			- set SLACK_BOT_TOKEN=xoxb-...
		- linux
			- export SLACK_APP_TOKEN=xapp-...
			- export SLACK_BOT_TOKEN=xoxb-...
	- ツールを実行します

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

- v0.4より **RULES**でボットを呼ぶとインタラクティブにホストを切り替えられるようになりました！

![2](https://user-images.githubusercontent.com/22161385/112720253-88290280-8f40-11eb-8974-d7cb8432a99a.png)
![3](https://user-images.githubusercontent.com/22161385/112720256-89f2c600-8f40-11eb-9a89-d7c0511e2bdd.png)

### その他の使い方

- toSLACK=(ファイル名)でサーバー上のファイルをアップできます。 (v0.5からはコードを動かしているサーバーじゃなくて選択しているリモートからアップできるようにしました)

今居るディレクトリパスを参照するのでパス指定せず、cdでディレクトリ移ってからファイル指定してください

![toSLACK](https://user-images.githubusercontent.com/22161385/112721551-c544c300-8f47-11eb-80d4-ea5ebf9504fb.png)

v0.5よりコンフィグでユーザー毎に機能の使用許可が割り振れます

- toSERVER=(アップ先)で**slackに最後にアップしたファイル**を接続しているサーバーにアップできます。(v0.4より)<br>

※(アップ先)はフォルダ名を指定します。画像の例のように . を指定した場合は**HOME**に配置されます。Windowsはフォルダ指定が難しいので一旦HOMEに置いて移動させた方が良いかも

![toSERVER](https://user-images.githubusercontent.com/22161385/112721553-c7a71d00-8f47-11eb-8982-161d89dfeb2a.png)

v0.5よりコンフィグでユーザー毎に機能の使用許可が割り振れます

- alias で長ったらしいコマンドの短縮名を付ける事ができます。

alias (**短縮名**)=(**長ったらしいコマンド**)で登録できます。aliasのみなら登録されている一覧を出します。

![alias1](https://user-images.githubusercontent.com/22161385/111068228-485b2780-850b-11eb-8c7d-0b808352882a.png)

alias (**短縮名**)= ←空 でaliasを解除できます。

![alias2](https://user-images.githubusercontent.com/22161385/111068233-4a24eb00-850b-11eb-934b-d385eba8e51d.png)

## コンフィグファイル

使うのにコンフィグファイルに動作を定義します。サンプルを参考にカスタマイズしてください。

#### v0.3より コンフィグファイルのホットリロードに対応しました。つまり、ファイルの変更を検知して自動で再読み込みします。

- [ALERT]
	- [REJECT]に定義した禁止コマンドを打った時にメンションで通報します
		- SlackのメンバーIDか、here、channnel、everyoneが定義できます

![1](https://user-images.githubusercontent.com/22161385/112720252-865f3f00-8f40-11eb-986a-58cd587776f1.png)

v0.5よりラベル化が出来ます。以下の場合、[REJECT]でescalation1ラベルを指定した

```
[ALERT]
escalation1	U024ZT3BHU5	here
```

- [ALLOWID]
	- Botの使用を許可するSlackのメンバーIDを指定します。[この辺りを参考](https://help.receptionist.jp/?p=1100)に確認してください
		- U01NJBRKGLD
- [REJECT]
	- 実行を許可しないコマンド等の文字列を列記します。以下のように**文字列が入ってたら**弾きます。

![reject](https://user-images.githubusercontent.com/22161385/110207742-e8400200-7ec8-11eb-83ed-46777efac839.png)

メモ: どこに入ってても無条件で弾きます。 \`\` を使う場合や、ls ;　　　rm -rfみたいにシェルで表現できる事が多いのでうまくバリデーションできないからです

- [HOSTS]
	- 接続するホスト情報を定義します。以下のように**タブ区切り**で定義します。
	- 定義名,IP/名前解決できるホスト名,SSHのポート番号,ユーザー名,※認証情報,使用するシェルのパス
	- test	127.0.0.1	22	slabot	secretpassword	/bin/bash
	- この**定義名**を**SETHOST**の後に書くことでコマンドの投げ先をスイッチさせます

※認証情報　**平文のパスワード**、**暗号化されたパスワード文字列**、**認証鍵のファイル**の3つのどれかを指定します

- v0.3より WindowsのSSH Serverに対応しました！

以下のようにWindowsのOpenSSHにコマンドを投げ込めるようにしました。

![wintarget](https://user-images.githubusercontent.com/22161385/111068235-4db87200-850b-11eb-87c2-c88ddee7d320.png)

使用するシェルのパス(SHEBANG)に以下のようにcmd /Cを指定する事で対応できます。/Cが大文字なので注意！

![winshebang](https://user-images.githubusercontent.com/22161385/111068236-4f823580-850b-11eb-9bda-3e63fe38471c.png)

- v0.4より コンフィグのテストが出来るようになりました！

デバッグモードで以下のようにでます。sshに失敗するようならルールの定義から削除されます

```
 -- HOSTS --
add RULE: windows fzk01 127.0.0.1 *** 22
add RULE: pi1 ady 192.168.0.200 *** 1880
add RULE: pi2 pi 192.168.0.220 *** 2880
```

※削除されて自動書き出しされた場合は定義が消えるので必要ならコンフィグのバックアップから再追記してください

- v0.4より 設定の永続化ができるようになりました！

コンフィグに以下のセクションが追加されています。こちらの後は各ユーザ事の定義が変更ドリブンで書き出され、永続化されます

```
[USERS]
```

※自動書き出し時には、自動でバックアップが出来ます。コンフィグ名に日付が追記されます

### コンフィグ記載例

```
[ALERT]
U01NJBRKGLD
here
[ALLOWID]
U01NJBRKGLD
[REJECT]
rm 
passwd
vi
[HOSTS]
windows	127.0.0.1	22	fzk01	myPassword	cmd /C
pi1	192.168.0.200	122	pi1	test.pem	/bin/ash
pi2	192.168.0.220	222	pi2	test.pem	/bin/bash
[USERS]
```

※v0.4からタブ区切りに変更されています

## 起動オプション

実行ファイルは以下、起動オプションがあります。

```
Usage of slabot:
  -alert
        [-alert=not allow user or command send alert.(true is enable)] (default true)
  -auto
        [-auto=config auto read/write mode (true is enable)] (default true)
  -bot string
        [-bot=slack bot name (@ + name)] (default "slabot")
  -check
        [-check=check rules. if connect fail to not use rule. (true is enable)] (default true)
  -config string
        [-config=config file)] (default ".slabot")
  -debug
        [-debug=debug mode (true is enable)]
  -decrypt string
        [-decrypt=password decrypt key string]
  -delUpload
        [-delUpload=file delete after upload (true is enable)]
  -encrypt string
        [-encrypt=password encrypt key string ex) pass:key (JUST ENCRYPT EXIT!)]
  -lock string
        [-lock=lock file for auto read/write)] (default ".lock")
  -log
        [-log=logging mode (true is enable)]
  -plainpassword
        [-plainpassword=use plain text password (true is enable)]
  -retry int
        [-retry=retry counts.] (default 10)
  -scp
        [-scp=need scp mode (true is enable)] (default true)
  -timeout int
        [-timeout=timeout count (second). ] (default 30)
  -toFile int
        [-toFile=if output over this value. be file.] (default 20)
```

## -alert
コンフィグの[ALERT]セクションの定義でアラートメンションを飛ばすのを有効かするかどうかです。デフォルトはtrueです。

### -auto
コンフィグの自動読み込み、書き出しを有効かするかどうかです。デフォルトはtrueです。

### -bot
botの名前です。slackから呼び出すときの名前を指定します。デフォルトは**slabot**で、slackから @slabot で呼びます。

### -check
コンフィグ読み込み時にホスト定義が接続可能かチェックするモードです。デフォルトはtrueです。オフにすると起動が早くなります。

### -config
読み込むコンフィグファイルを指定します。デフォルトは実行ファイルのカレントにある **.slabot** です。

### -debug
デバッグモードで起動します。指定すると内部動作情報が色々出てきます。

### -decrypt
コンフィグに**暗号化されたパスワード文字列**を使う場合に、**複合するためのキー**を指定します。

### -delUpload
サーバーにtoSERVERでアップロードした後にslack上のファイルを消すかどうかです。デフォルトはfalseです。

### -encrypt
コンフィグに**暗号化されたパスワード文字列**を使う場合に、**パスワード**と**複合するためのキー**を指定して暗号文字を生成します。<br>
出力した文字列をコンフィグの認証情報部分に張り付けてください。

```
$ slabot.exe -encrypt=mypassword:decryptkey
Encrypt: 5NVkTdvu5-g0pQCcy0RpOnxuaLFplSJZ0SIjtQqyVZKMGcFIuiY=
```

このオプションを指定した場合は、暗号文字生成後に実行終了します。(既に動いているプロセスには影響はない)

### -lock
コンフィグの自動読み込み、書き出しの時のロックファイル名です。書き出しと読み込みが衝突するのを防ぎます。共有ファイルシステム上でのバッティングを防ぎます。

### -log
ログ出力モードです。デバッグログが以下のように年・月・日・時のフォーマットで出力されます。

![logging](https://user-images.githubusercontent.com/22161385/111068741-61fd6e80-850d-11eb-8c4a-c890453bc251.png)

### -plainpassword
パスワード平文モードです。trueにすると、コンフィグの認証情報部分の文字列を複合せずに平文のまま認証します。

### -retry
内部でscp、sshをリトライする回数です。失敗時にリトライします。

### -scp
scpでシェルを転送しないモードです。コマンドのみ流すので**応答スピードが倍**になります<br>
が反面、使えるコマンドに**ダブルクォーテーション(")が使えなくなります**<br>
@slabot echo "t e s t" > sample みたいなのが出来なくなるってことっすね。

### -timeout
sshでコマンドを投げた後のタイムアウト値です。デフォルトは**30**で30秒を越える場合はコマンド実行に失敗することになります。

### -toFile
長い行数の出力をテキストファイルにして、アップロードする際の閾値になります。デフォルトは**20**で20行を越える場合にファイルに変換されます。

## ライセンス

BSD-2-Clause License, ISC License, BSD-3-Clause License,
