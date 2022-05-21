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

- v0.7
	- 定義名をIDじゃなくてユーザー名にしても名前解決できるようにしました
		- IDで書いてあるとこれ誰用の定義だっけ？ってなってしまうのでユーザー名で書けるようにしました
	- コマンドの先頭に#を付けることでscpしないで実行する高速実行モードをつけました
		- scpでコマンド送ってから実行するのを、実行だけやるので倍速になります

- v0.8
	- 許可されたコマンドだけ実行できる制限モードを付けました
		- 禁止ワードを弾くと、反対の制限されたコマンドだけ実行できるモードでより細かくロールをつけれます
	- 各アカウントに利用期限を設定出来るようにしました
		- アカウントに有効期限の概念を入れました。これで未使用アカウントは自動的に無効化されます。
	- 利用期限を定期的にレポートするようにしました
		- 特定のチャンネルにレポートを送信し、棚卸出来るようにしました
	- コンフィグを外から設定出来るようにADMINモードを付けました
		- 設定ファイルを書き換えなくても設定変更出来るようにしました

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

- v0.7より **#** を先頭につけることで、バッチをscpしてから実行するモードを直接実行する、-scp=falseにしたのと同じ高速実行モードにします

![image](https://user-images.githubusercontent.com/22161385/126061864-40c30544-8477-4abc-bee5-0dfab4aa0f85.png)

注) -scp=falseと同じでダブルクォーテーションがあるコマンドは実行できません

### その他の使い方

- toSLACK=(ファイル名)でサーバー上のファイルをアップできます。 (v0.5からはコードを動かしているサーバーじゃなくて選択しているリモートからアップできるようにしました)

今居るディレクトリパスを参照するのでパス指定せず、cdでディレクトリ移ってからファイル指定してください

![toSLACK](https://user-images.githubusercontent.com/22161385/112721551-c544c300-8f47-11eb-80d4-ea5ebf9504fb.png)

v0.5よりコンフィグでユーザー毎にこの機能の使用許可が割り振れます

- toSERVER=(アップ先)で**slackに最後にアップしたファイル**を接続しているサーバーにアップできます。(v0.4より)<br>

※(アップ先)はフォルダ名を指定します。画像の例のように . を指定した場合は**HOME**に配置されます。Windowsはフォルダ指定が難しいので一旦HOMEに置いて移動させた方が良いかも

![toSERVER](https://user-images.githubusercontent.com/22161385/112721553-c7a71d00-8f47-11eb-8982-161d89dfeb2a.png)

v0.5よりコンフィグでユーザー毎に機能のこの使用許可が割り振れます

- alias で長ったらしいコマンドの短縮名を付ける事ができます。

alias (**短縮名**)=(**長ったらしいコマンド**)で登録できます。aliasのみなら登録されている一覧を出します。

![alias1](https://user-images.githubusercontent.com/22161385/111068228-485b2780-850b-11eb-8c7d-0b808352882a.png)

alias (**短縮名**)= ←空 でaliasを解除できます。

![alias2](https://user-images.githubusercontent.com/22161385/111068233-4a24eb00-850b-11eb-934b-d385eba8e51d.png)

注) aliasは制限コマンドを回避出来てしまうため、制限モードのユーザーには使えません

#### 特権モード (v0.8より)

SLACK経由でコンフィグを書き換えられる特権モードです。<br>

このモードはコンフィグの[ADMINS]に定義された特権アカウントのみ実行が可能です。<br>
使い方としてコンフィグの**タブ区切り**を**カンマ**に書き換えてボットに投げます。<br>

例１）
![image](https://user-images.githubusercontent.com/22161385/169651436-9d6d1d1d-099c-4ea5-8efd-018252a6e640.png)
例２）
![image](https://user-images.githubusercontent.com/22161385/169651459-42f8bbf1-6eec-4c0e-a7c8-3f8e997b2c22.png)
例３）
![image](https://user-images.githubusercontent.com/22161385/169651474-db19e954-87b5-422b-a7c4-03a54d81ae7e.png)
※平文でパスワード入れてますが、暗号化したものか、鍵認証にした方が良いです<br>

二番目のパラメータに**DELETE**を指定、**三番目に定義済みのラベル**を指定すると定義を消せます

例１）
![image](https://user-images.githubusercontent.com/22161385/169651546-8cf4d929-adfe-4573-a4f2-950e7e923139.png)
例２）
![image](https://user-images.githubusercontent.com/22161385/169651512-1f1d1851-1343-4a74-a3d5-c000558c83be.png)

そうでないアカウントが実行した場合はセキュリティアラートが発行されます。<br>

![image](https://user-images.githubusercontent.com/22161385/169651384-47f41bcd-97a6-4475-9abc-1809ab7e3931.png)

## コンフィグファイル

使うのにコンフィグファイルに動作を定義します。サンプルを参考にカスタマイズしてください。

#### v0.3より コンフィグファイルのホットリロードに対応しました。つまり、ファイルの変更を検知して自動で再読み込みします。

- [ALERT]
	- [REJECT]に定義した禁止コマンドを打った時にメンションで通報します
		- SlackのユーザーIDか、here、channnel、everyoneが定義できます

![1](https://user-images.githubusercontent.com/22161385/112720252-865f3f00-8f40-11eb-986a-58cd587776f1.png)

v0.5よりラベル化が出来ます。以下の場合、[REJECT]でescalation1ラベルを指定した場合に次のタブ区切りで指定したユーザーにメンションされます

```
[ALERT]
escalation1	U024ZT3BHU5	here
```

先頭のラベル以降はタブ区切りで複数ユーザーを指定できます。<br>
ただし指定はユーザーのIDで指定してください。[この辺りを参考](https://help.receptionist.jp/?p=1100)に確認してください<br>
v0.7より) 指定はユーザーIDだけでなく、**ユーザー名**で指定も出来ます

- [ALLOWID]
	- Botの使用を許可するSlackのロールを指定します。

```
[ALLOWID]
user	hostlabel1	RW	allow	allowrule1	*
```

SlackのユーザーID、アクセス可能なホストのラベル、ファイルのアップロード・ダウンロードの権限、禁止操作をするルールのラベルを指定します。<br>
ユーザーIDの指定は[この辺りを参考](https://help.receptionist.jp/?p=1100)に確認してください。<br>
ホストのラベルは[HOSTS]の定義の先頭と紐づきます。<br>
RWの部分はRWか、Rか、その他が指定できます。RWはtoSLACK、toSERVER両方許可します。RはtoSLACKのみ。その他は両方使えません。<br>
禁止操作をするルールのラベルは[REJECT]の先頭で指定するラベルになります<br>
つぎに**allow / reject**で制限モードを指定します。allowは許可されたコマンドだけ実行できます。リジェクトは逆で禁止されたコマンドは実行できません。<br>
モードの指定の後に、制限モードに指定するルールラベル名を書きます。**allowなら[ALLOW]、rejectなら[REJECT]**からラベルを指定します。
続いて使用期限を書きます。**YYYY/MM/DD** のフォーマットで書いてください。

v0.7より) 指定はユーザーIDだけでなく、**ユーザー名**で指定も出来ます
v0.8より）３つのパラメーターが追加されています。上記でいうところのRWの後の３個です。

- [REJECT]
	- **実行を許可しない**コマンド等の文字列を列記します。以下のように**文字列が入ってたら**弾きます。

![reject](https://user-images.githubusercontent.com/22161385/110207742-e8400200-7ec8-11eb-83ed-46777efac839.png)

先頭はルールのラベルです。次はアラートするルールのラベル、その次からは実行を禁止するコマンドです。実行を禁止するコマンドはタブ区切りで複数を指定できます。<br>

```
[REJECT]
rejectrule1	escalation1	rm	passwd	vi
```

メモ: どこに入ってても無条件で弾きます。 \`\` を使う場合や、ls ;　　　rm -rfみたいにシェルで表現できる事が多いのでうまくバリデーションできないからです

- [HOSTS]
	- 接続するホスト情報を定義します。以下のように**タブ区切り**で定義します。
	- ラベル、定義名,IP/名前解決できるホスト名,SSHのポート番号,ユーザー名,※認証情報,使用するシェルのパス
	- hostlabel1	test	127.0.0.1	22	slabot	secretpassword	/bin/bash
	- この**定義名**を**SETHOST**の後に書くことでコマンドの投げ先をスイッチさせます

[ALLOWID]で定義したラベル名と紐づきますのでユーザーごとに指定できるホストが制限できます。

```
[HOSTS]
hostlabel1	pi1	192.168.0.1	22	pi1	myPassword1	/bin/bash
hostlabel2	pi2	192.168.0.2	22	pi2	myPassword2	/bin/ash
```

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

- [ALLOW]
	- **実行を許可したい**コマンド等の文字列を列記します。指定した文字、またはスペース付きの場合に許可します

先頭はルールのラベルです。次はアラートするルールのラベル、その次からは実行を許可するコマンドです。実行を許可するコマンドはタブ区切りで複数を指定できます。<br>

```
[REJECT]
allowrule1	escalation1	cd	ls	cat	ps	df	find
```

メモ: alias禁止と同様にパイプも使えません

- [ADMINS]
	- コンフィグを**SLACK経由で書き換えられる**特権IDを指定します

ID名を書きます。改行区切りで複数指定できます。

```
[ADMINS]
admin
```

- [REPORT]
	- **定期的にアカウント使用期限をレポート**するチャンネル名を定義します

チャンネル名を書きます。指定できるチャンネルは一つのみです。

```
[REPORT]
C0256BTKP54
```

メモ: alias禁止と同様にパイプも使えません

### コンフィグ記載例

```
[ALERT]
escalation1	U024ZT3BHU5	here
[ALLOWID]
U024ZT3BHU5	hostlabel1	RW	rejectrule1
[REJECT]
rejectrule1	escalation1	rm	passwd	vi
[HOSTS]
hostlabel1	pi1	192.168.0.1	22	pi1	myPassword1	/bin/bash
hostlabel2	pi2	192.168.0.2	22	pi2	myPassword2	/bin/ash
[USERS]
```

※v0.4からタブ区切りに変更されています

#### v0.7より

v0.7から指定はユーザーIDだけでなく、**ユーザー名**で指定も出来ます

```
[ALERT]
escalation1	adminuser	here
[ALLOWID]
adminuser	hostlabel1	RW	rejectrule1
[REJECT]
rejectrule1	escalation1	rm	passwd	vi
[HOSTS]
hostlabel1	pi1	192.168.0.1	22	pi1	myPassword1	/bin/bash
hostlabel2	pi2	192.168.0.2	22	pi2	myPassword2	/bin/ash
[USERS]
U024ZT3BHU5	~/	0	
```

### v0.8より

ここではv0.7からの変更点を書きます。
[ALLOWID]のファイル操作権限の指定の後に、制限モードの指定、制限ルールの指定、アカウントの期限が追加されました。<br>
[ALLOW]では[REJECT]と同じように許可するコマンドをタブ区切りで設定します。<br>
[ADMINS]には特権コマンドを利用できるアカウントを指定します。<br>
[REPORT]には定期リポートをアップするチャンネルIDを指定します。<br>

```
[ALERT]
escalation1	adminuser	here
[ALLOWID]
user	hostlabel1	RW	allow	allowrule1	*
admin	hostlabel1	RW	reject	rejectrule1	2022/05/24
[REJECT]
rejectrule1	escalation1	rm	passwd	vi
[HOSTS]
hostlabel1	pi1	192.168.0.1	22	pi1	myPassword1	/bin/bash
hostlabel2	pi2	192.168.0.2	22	pi2	myPassword2	/bin/ash
[USERS]
U024ZT3BHU5	~/	0
[ALLOW]
allowrule1	escalation1	cd	ls	cat	ps	df	find
[ADMINS]
admin
[REPORT]
C0256BTKP54
```

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
  -idlookup
        [-idlookup=resolve to ID definition (true is enable)] (default true)
  -lock string
        [-lock=lock file for auto read/write)] (default ".lock")
  -log
        [-log=logging mode (true is enable)]
  -loop int
        [-loop=user check loop time (Hour). ] (default 24)
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

### -idlookup
ユーザー名で定義しても、IDに名前解決して動作するモードです。v0.6まで) U024ZT3BHU5　→ v0.7から) adminuser

### -lock
コンフィグの自動読み込み、書き出しの時のロックファイル名です。書き出しと読み込みが衝突するのを防ぎます。共有ファイルシステム上でのバッティングを防ぎます。

### -log
ログ出力モードです。デバッグログが以下のように年・月・日・時のフォーマットで出力されます。

![logging](https://user-images.githubusercontent.com/22161385/111068741-61fd6e80-850d-11eb-8c4a-c890453bc251.png)

### -loop
コンフィグに指定したチャンネルにレポートをあげる時間の間隔です。単位は一時間でデフォルトは２４時間です。

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
