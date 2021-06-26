/*
 * Bringing true chatops with slack to your team.
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   BSD-2-Clause License, ISC License, BSD-3-Clause License
 */
package main

import (
	"crypto/aes"
	"crypto/cipher"
	crt "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"

	"github.com/appleboy/easyssh-proxy"
	"github.com/blacknon/go-scplib"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/ssh"
	"gopkg.in/ini.v1"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
)

const (
	totalExecuteNum int = 10
)

var (
	secAlert   bool
	debug      bool
	logging    bool
	needSCP    bool
	delUpload  bool
	sshTimeout int
	RETRY      int
	toFile     int
	alerts     []alertData
	allows     []allowData
	rejects    []rejectData
	hosts      []hostsData
	udata      []userData
	botName    string
	autoRW     bool
	lockFile   string
	configFile string
)

type alertData struct {
	LABEL string
	USERS []string
}

type allowData struct {
	ID         string
	LABEL      string
	PERMISSION int
	REJECT     string
}

type rejectData struct {
	LABEL    string
	ALERT    string
	COMMANDS []string
}

type userData struct {
	ID    string
	PWD   string
	HOST  int
	ALIAS []string
}

type hostsData struct {
	LABEL   string
	RULE    string
	HOST    string
	PORT    string
	USER    string
	PASSWD  string
	SHEBANG string
}

type responseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type receiveData struct {
	User    string `json:"user"`
	Command string `json:"command"`
}

func main() {
	sig := make(chan string, totalExecuteNum)

	_secAlert := flag.Bool("alert", true, "[-alert=not allow user or command send alert.(true is enable)]")
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_Config := flag.String("config", "slabot.ini", "[-config=config file)]")
	_needSCP := flag.Bool("scp", true, "[-scp=need scp mode (true is enable)]")
	_RETRY := flag.Int("retry", 10, "[-retry=retry counts.]")
	_plainpassword := flag.Bool("plainpassword", false, "[-plainpassword=use plain text password (true is enable)]")
	_decryptkey := flag.String("decrypt", "", "[-decrypt=password decrypt key string]")
	_encrypt := flag.String("encrypt", "", "[-encrypt=password encrypt key string ex) pass:key (JUST ENCRYPT EXIT!)]")
	_TOFILE := flag.Int("toFile", 20, "[-toFile=if output over this value. be file.]")
	_sshTimeout := flag.Int("timeout", 30, "[-timeout=timeout count (second). ]")
	_botName := flag.String("bot", "slabot", "[-bot=slack bot name (@ + name)]")

	_autoRW := flag.Bool("auto", true, "[-auto=config auto read/write mode (true is enable)]")
	_lockFile := flag.String("lock", ".lock", "[-lock=lock file for auto read/write)]")
	_delUpload := flag.Bool("delUpload", false, "[-delUpload=file delete after upload (true is enable)]")
	_checkRules := flag.Bool("check", true, "[-check=check rules. if connect fail to not use rule. (true is enable)]")

	flag.Parse()

	delUpload = bool(*_delUpload)
	needSCP = bool(*_needSCP)
	secAlert = bool(*_secAlert)
	debug = bool(*_Debug)
	logging = bool(*_Logging)
	configFile = string(*_Config)
	RETRY = int(*_RETRY)
	sshTimeout = int(*_sshTimeout)
	toFile = int(*_TOFILE)
	botName = string(*_botName)

	autoRW = bool(*_autoRW)
	lockFile = string(*_lockFile)

	if len(*_encrypt) > 0 && strings.Index(*_encrypt, ":") != -1 {
		strs := strings.Split(*_encrypt, ":")
		enc, err := encrypt(strs[0], []byte(addSpace(strs[1])))
		if err == nil {
			fmt.Println("Encrypt: " + enc)
			os.Exit(0)
		} else {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if Exists(configFile) == true {
		loadConfig(addSpace(*_decryptkey), *_plainpassword, *_checkRules)
	} else {
		fmt.Printf("Fail to read config file: %v\n", configFile)
		os.Exit(1)
	}

	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
	}
	//defer watcher.Close()

	if autoRW == true {
		go func() {
			for {
				select {
				case <-watcher.Events:
					if Exists(lockFile) == false {
						time.Sleep(1 * time.Second)
						loadConfig(addSpace(*_decryptkey), *_plainpassword, false)
					} else {
						fmt.Println(" - config read locked! - ")
					}
				case <-watcher.Errors:
					fmt.Println("ERROR", err)
				}
			}
		}()
	}

	if err := watcher.Add(configFile); err != nil {
		fmt.Println("ERROR", err)
	}

	appToken := os.Getenv("SLACK_APP_TOKEN")
	if appToken == "" {
		fmt.Fprintf(os.Stderr, "SLACK_APP_TOKEN must be set.\n")
		os.Exit(1)
	}

	if !strings.HasPrefix(appToken, "xapp-") {
		fmt.Fprintf(os.Stderr, "SLACK_APP_TOKEN must have the prefix \"xapp-\".")
	}

	botToken := os.Getenv("SLACK_BOT_TOKEN")
	if botToken == "" {
		fmt.Fprintf(os.Stderr, "SLACK_BOT_TOKEN must be set.\n")
		os.Exit(1)
	}

	if !strings.HasPrefix(botToken, "xoxb-") {
		fmt.Fprintf(os.Stderr, "SLACK_BOT_TOKEN must have the prefix \"xoxb-\".")
	}

	api := slack.New(
		botToken,
		slack.OptionDebug(debug),
		slack.OptionLog(log.New(os.Stdout, "api: ", log.Lshortfile|log.LstdFlags)),
		slack.OptionAppLevelToken(appToken),
	)

	go socketMode(sig, api)

	go func() {
		for {
			select {
			case v := <-sig:
				strs := strings.Split(v, "\t")
				stra := ""

				switch len(strs) {
				case 1:
					stra = "Error: not execute!"
				case 2:
					stra = "<@" + strs[1] + ">\nError: not execute!"
				case 3:
					stra = "<@" + strs[1] + ">\n```\n" + strs[2] + "```"
				case 4:
					tmpFile := "tmp." + strs[1]

					if strings.Count(strs[3], "\n") > toFile {
						fmt.Println("upload "+tmpFile+".txt", tmpFile+".txt", strs[0])
						params := slack.FileUploadParameters{
							Title:    "upload terminal",
							Filetype: "txt",
							File:     tmpFile + ".txt",
							Content:  strs[2] + strs[3],
							Channels: []string{strs[0]},
						}
						_, err := api.UploadFile(params)
						if err != nil {
							fmt.Printf("%s\n", err)
							stra = "<@" + strs[1] + ">\nError: terminal not upload!"
						} else {
							stra = "<@" + strs[1] + ">\nSuccess: terminal upload success!"
						}
					} else {
						stra = "<@" + strs[1] + ">\n```\n" + strs[2] + strs[3] + "```"
					}
				}
				_, _, err := api.PostMessage(strs[0], slack.MsgOptionText(stra, false))
				if err != nil {
					fmt.Printf("failed posting message: %v", err)
				}
			}
		}
	}()

	for {
		fmt.Printf(".")
		time.Sleep(time.Second * 3)
	}
	os.Exit(0)
}

func socketMode(sig chan string, api *slack.Client) {
	client := socketmode.New(
		api,
		socketmode.OptionDebug(debug),
		socketmode.OptionLog(log.New(os.Stdout, "socketmode: ", log.Lshortfile|log.LstdFlags)),
	)

	go func() {
		for evt := range client.Events {
			switch evt.Type {
			case socketmode.EventTypeConnecting:
				fmt.Println("Connecting to Slack with Socket Mode...")
			case socketmode.EventTypeConnectionError:
				fmt.Println("Connection failed. Retrying later...")
			case socketmode.EventTypeConnected:
				fmt.Println("Connected to Slack with Socket Mode.")
			case socketmode.EventTypeEventsAPI:
				eventsAPIEvent, ok := evt.Data.(slackevents.EventsAPIEvent)
				if !ok {
					fmt.Printf("Ignored %+v\n", evt)

					continue
				}

				client.Ack(*evt.Request)

				switch eventsAPIEvent.Type {
				case slackevents.CallbackEvent:
					innerEvent := eventsAPIEvent.InnerEvent
					switch event := innerEvent.Data.(type) {
					case *slackevents.AppMentionEvent:
						message := strings.Split(event.Text, " ")
						if len(message) > 1 {
							command := strings.Replace(event.Text, message[0]+" ", "", 1)

							debugLog("socket call: " + event.User + " " + command)

							if command == "RULES" {
								rules := returnRules(checkUsers(event.User))

								if len(rules) > 0 {
									text := slack.NewTextBlockObject(slack.MarkdownType, "Please select *RULE*.", false, false)
									textSection := slack.NewSectionBlock(text, nil, nil)

									options := make([]*slack.OptionBlockObject, 0, len(rules))
									for _, v := range rules {
										optionText := slack.NewTextBlockObject(slack.PlainTextType, v, false, false)
										options = append(options, slack.NewOptionBlockObject(v, optionText, nil))
									}

									placeholder := slack.NewTextBlockObject(slack.PlainTextType, "Select RULE", false, false)
									selectMenu := slack.NewOptionsSelectBlockElement(slack.OptTypeStatic, placeholder, "", options...)

									actionBlock := slack.NewActionBlock("rules", selectMenu)

									fallbackText := slack.MsgOptionText("This client is not supported.", false)
									blocks := slack.MsgOptionBlocks(textSection, actionBlock)

									if _, err := api.PostEphemeral(event.Channel, event.User, fallbackText, blocks); err != nil {
										log.Println(err)
										return
									}
								} else {
									_, _, err := api.PostMessage(event.Channel, slack.MsgOptionText("Error: "+event.User+" use no rules.", false))
									if err != nil {
										fmt.Printf("failed posting message: %v", err)
									}
								}
							} else {
								trueFalse, text := eventSwitcher(sig, event.User, command, event.Channel, api)

								if trueFalse == false {
									text = "Error: " + text
								}
								if len(text) > 0 {
									_, _, err := api.PostMessage(event.Channel, slack.MsgOptionText(text, false))
									if err != nil {
										fmt.Printf("failed posting message: %v", err)
									}
								}
							}
						}
					case *slackevents.MemberJoinedChannelEvent:
						fmt.Printf("user %q joined to channel %q", event.User, event.Channel)
					}
				default:
					client.Debugf("unsupported Events API event received")
				}
			case socketmode.EventTypeInteractive:
				callback, ok := evt.Data.(slack.InteractionCallback)
				if !ok {
					fmt.Printf("Ignored %+v\n", evt)

					continue
				}

				debugLog("Interaction received: " + string(callback.RawState))

				stra := strings.Split(string(callback.RawState), ",")
				val := ""
				for i := 0; i < len(stra); i++ {
					if strings.Index(stra[i], "\"text\":") == 0 {
						val = stra[i]
						break
					}
				}
				vals := strings.Split(val, ":")
				ruleName := strings.Replace(vals[1], "\"", "", -1)
				userInt := checkUsers(callback.User.ID)
				udata[userInt].HOST = hostCheck(ruleName)

				text := "<@" + udata[userInt].ID + "> " + ruleName + " : host set"
				udata[userInt].PWD = setHome()
				writeUsersData()

				_, _, err := api.PostMessage(callback.Channel.GroupConversation.Conversation.ID, slack.MsgOptionText(text, false))
				if err != nil {
					fmt.Printf("failed posting message: %v", err)
				}

				debugLog(callback.User.ID + " : select " + strings.Replace(vals[1], "\"", "", -1))

				client.Ack(*evt.Request)
			default:
				fmt.Fprintf(os.Stderr, "Unexpected event type received: %s\n", evt.Type)
			}
		}
	}()
	client.Run()
}

func returnAlias(userInt int) string {
	strs := ""
	for i := 0; i < len(udata[userInt].ALIAS); i++ {
		s := strconv.Itoa(i + 1)
		strs = strs + "[" + s + "] " + udata[userInt].ALIAS[i] + "\n"
	}
	return strs
}

func returnHosts() string {
	strs := ""
	for i := 0; i < len(hosts); i++ {
		s := strconv.Itoa(i + 1)
		strs = strs + "[" + s + "] " + hosts[i].RULE + ": " + hosts[i].HOST + " " + hosts[i].PORT + " " + hosts[i].USER + " " + hosts[i].SHEBANG + "\n"
	}
	return strs
}

func returnRules(userInt int) []string {
	var strs []string

	for i := 0; i < len(hosts); i++ {
		if allows[userInt].LABEL == hosts[i].LABEL {
			strs = append(strs, hosts[i].RULE)
		}
	}
	return strs
}

func replaceAlias(userInt int, command string) string {
	for i := 0; i < len(udata[userInt].ALIAS); i++ {
		stra := strings.Split(udata[userInt].ALIAS[i], "=")
		if strings.Index(command+" ", stra[0]+" ") == 0 {
			return strings.Replace(command, stra[0], stra[1], 1)
		}
	}
	return command
}

func deleteAlias(userInt int, command string) {
	for i := 0; i < len(udata[userInt].ALIAS); i++ {
		stra := strings.Split(udata[userInt].ALIAS[i], "=")
		if strings.Index(command, stra[0]) == 0 {
			udata[userInt].ALIAS = unset(udata[userInt].ALIAS, i)
		}
	}
}

func unset(s []string, i int) []string {
	if i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}

func eventSwitcher(sig chan string, User, Command, channel string, api *slack.Client) (bool, string) {
	userInt := checkUsers(User)

	// for debug
	//udata[userInt].HOST = 0
	// for debug

	trueFalse := false
	data := ""

	debugLog("User: " + User + " Command: " + Command)

	if allowUser(User) == false {
		trueFalse = false
		data = User + " : user not allow"
		if secAlert == true {
			data = data + "\n [Security Alert!] " + alertUsers()
		}
	} else if strings.Index(Command, "alias") == 0 {
		if Command == "alias" {
			strs := returnAlias(userInt)
			if len(strs) == 0 {
				strs = "no alias!"
			}
			return true, "<@" + udata[userInt].ID + ">\n```\n" + strs + "```"
		}
		if strings.Index(Command, "alias ") == 0 && strings.Index(Command, "=") != -1 {
			stra := strings.Split(Command, "=")
			if len(stra[1]) == 0 {
				Command := strings.Replace(Command, "alias ", "", 1)
				deleteAlias(userInt, Command)
				trueFalse = true
				data = "<@" + udata[userInt].ID + "> " + Command + " : alias delete"
				writeUsersData()
			} else {
				Command := strings.Replace(Command, "alias ", "", 1)
				udata[userInt].ALIAS = append(udata[userInt].ALIAS, Command)
				trueFalse = true
				data = "<@" + udata[userInt].ID + "> " + Command + " : alias set"
				writeUsersData()
			}
		} else {
			trueFalse = false
			data = "<@" + udata[userInt].ID + "> " + Command + " : alias set fail"
		}

	} else if strings.Index(Command, "SETHOST") == 0 {
		if Command == "SETHOST" {
			strs := returnHosts()
			if len(strs) == 0 {
				strs = "no hosts!"
			}
			return true, "<@" + udata[userInt].ID + ">\n```\n" + strs + "```"
		}
		if strings.Index(Command, "SETHOST=") == 0 {
			stra := strings.Split(Command, "SETHOST=")
			hostInt := hostCheck(stra[1])
			if hostInt == -1 {
				debugLog("Error: host not found. " + User + " " + Command)

				trueFalse = false
				data = "<@" + udata[userInt].ID + "> " + stra[1] + " : host not found"
			} else {
				udata[userInt].HOST = hostInt

				trueFalse = true
				data = "<@" + udata[userInt].ID + "> " + stra[1] + " : host set"
				udata[userInt].PWD = setHome()
				writeUsersData()
			}
		}
	} else if strings.Index(Command, "toSERVER=") == 0 && udata[userInt].HOST != -1 {
		if allows[userInt].PERMISSION == 2 {
			stra := strings.Split(Command, "toSERVER=")
			trueFalse, data = uploadFile(userInt, stra[1], api)
		} else {
			trueFalse = false
			data = "<@" + udata[userInt].ID + "> : not allow upload"
			if secAlert == true {
				data = data + "\n [Security Alert!] " + alertUsers()
			}
		}
	} else {
		if checkHost(User) == true {
			Command = replaceAlias(userInt, Command)
			trueFalse, data = checkPreExecuter(sig, User, Command, udata[userInt].HOST, channel, api)
		} else {
			trueFalse = false
			data = "<@" + udata[userInt].ID + "> " + Command + ": host not set"
		}
	}
	return trueFalse, data
}

func uploadFile(userInt int, path string, api *slack.Client) (bool, string) {
	params := slack.GetFilesParameters{
		User:  udata[userInt].ID,
		Count: 1,
	}

	files, _, err := api.GetFiles(params)
	if err != nil || len(files) == 0 {
		fmt.Println(err)
		return false, "get files error"
	}

	file, err := os.Create(files[0].Name)
	if err != nil {
		fmt.Println(err)
		return false, "file not create: " + files[0].Name
	}

	error := api.GetFile(files[0].URLPrivateDownload, file)
	if err != nil {
		fmt.Println(error)
		return false, "file not download: " + files[0].Name
	}

	file.Close()

	if len(path) == 0 {
		path = udata[userInt].PWD
	}

	if scpDo(false, udata[userInt].HOST, files[0].Name, path) == false {
		return false, "file not scp: " + files[0].Name
	}

	if err := os.Remove(files[0].Name); err != nil {
		fmt.Println(err)
	}

	if delUpload == true {
		err = api.DeleteFile(files[0].ID)
		if err != nil {
			fmt.Printf("%s\n", err)
			return false, "file upload success and file not delete on slack: " + files[0].Name
		}
	}

	return true, "file upload success: " + files[0].Name
}

func writeUsersData() {
	if autoRW == true && Exists(lockFile) == false {
		lfile, err := os.Create(lockFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		lfile.Close()

		const layout = "2006-01-02_15"
		t := time.Now()
		if err := os.Rename(configFile, configFile+"_"+t.Format(layout)); err != nil {
			fmt.Println(err)
			return
		}

		file, err := os.Create(configFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		_, err = file.WriteString("[ALERT]\n")
		for i := 0; i < len(alerts); i++ {
			_, err = file.WriteString(alerts[i].LABEL + "\t")
			for r := 0; r < len(alerts[i].USERS); r++ {
				if r == 0 {
					_, err = file.WriteString(alerts[i].USERS[r])
				} else {
					_, err = file.WriteString("\t" + alerts[i].USERS[r])
				}
			}
			_, err = file.WriteString("\n")
		}

		_, err = file.WriteString("[ALLOWID]\n")
		for i := 0; i < len(allows); i++ {
			if allows[i].PERMISSION == 1 {
				_, err = file.WriteString(allows[i].ID + "\t" + allows[i].LABEL + "\tR\t" + allows[i].REJECT + "\n")
			} else if allows[i].PERMISSION == 2 {
				_, err = file.WriteString(allows[i].ID + "\t" + allows[i].LABEL + "\tRW\t" + allows[i].REJECT + "\n")
			} else {
				_, err = file.WriteString(allows[i].ID + "\t" + allows[i].LABEL + "\tNO\t" + allows[i].REJECT + "\n")
			}
		}

		_, err = file.WriteString("[REJECT]\n")
		for i := 0; i < len(rejects); i++ {
			_, err = file.WriteString(rejects[i].ALERT + "\t" + rejects[i].LABEL + "\t")
			for r := 0; r < len(rejects[i].COMMANDS); r++ {
				if r == 0 {
					_, err = file.WriteString(rejects[i].COMMANDS[r])
				} else {
					_, err = file.WriteString("\t" + rejects[i].COMMANDS[r])
				}
			}
			_, err = file.WriteString("\n")
		}

		_, err = file.WriteString("[HOSTS]\n")
		for i := 0; i < len(hosts); i++ {
			_, err = file.WriteString(hosts[i].LABEL + "\t" + hosts[i].RULE + "\t" + hosts[i].HOST + "\t" + hosts[i].PORT + "\t" + hosts[i].USER + "\t" + hosts[i].PASSWD + "\t" + hosts[i].SHEBANG + "\n")
		}

		_, err = file.WriteString("[USERS]\n")
		for i := 0; i < len(udata); i++ {
			aliasStr := getAliasToStr(udata[i].ALIAS)
			_, err = file.WriteString(udata[i].ID + "\t" + udata[i].PWD + "\t" + strconv.Itoa(udata[i].HOST) + "\t" + aliasStr + "\n")
		}

		if err := os.Remove(lockFile); err != nil {
			fmt.Println(err)
		}
		return
	}
}

func getAliasToStr(strAll []string) string {
	strs := ""
	for i := 0; i < len(strAll); i++ {
		if len(strAll[i]) > 0 {
			strs = strs + "\t" + strAll[i]
		}
	}
	return strs
}

func debugLog(message string) {
	var file *os.File
	var err error

	if debug == true {
		fmt.Println(message)
	}

	if logging == false {
		return
	}

	const layout = "2006-01-02_15"
	t := time.Now()
	filename := botName + "_" + t.Format(layout) + ".log"

	if Exists(filename) == true {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0666)
	} else {
		file, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	}

	if err != nil {
		log.Fatal(err)
		return
	}
	defer file.Close()
	fmt.Fprintln(file, message)
}

func writeFile(filename, stra string, userInt int, dirFlag bool) bool {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer file.Close()

	if dirFlag == true {
		_, err = file.WriteString("cd " + udata[userInt].PWD + "\n")
	}
	_, err = file.WriteString(stra + "\n")
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func loadConfig(decryptstr string, plainpassword bool, checkRules bool) {
	loadOptions := ini.LoadOptions{}
	loadOptions.UnparseableSections = []string{"ALERT", "ALLOWID", "REJECT", "HOSTS", "USERS"}

	cfg, err := ini.LoadSources(loadOptions, configFile)
	if err != nil {
		fmt.Printf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	alerts = nil
	allows = nil
	rejects = nil
	hosts = nil
	udata = nil

	setStructs("ALERT", cfg.Section("ALERT").Body(), 0, "", false, false)
	setStructs("ALLOWID", cfg.Section("ALLOWID").Body(), 1, "", false, false)
	setStructs("REJECT", cfg.Section("REJECT").Body(), 2, "", false, false)
	setStructs("HOSTS", cfg.Section("HOSTS").Body(), 3, decryptstr, plainpassword, checkRules)
	setStructs("USERS", cfg.Section("USERS").Body(), 4, "", false, false)
}

func setStructs(configType, datas string, flag int, decryptstr string, plainpassword, checkRules bool) {
	cFlag := 0
	debugLog(" -- " + configType + " --")

	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if len(v) > 0 {
			if strings.Index(v, "\t") != -1 {
				strs := strings.Split(v, "\t")

				switch flag {
				case 0:
					if len(strs) > 1 {
						var strr []string

						for i := 1; i < len(strs); i++ {
							strr = append(strr, strs[i])
						}
						alerts = append(alerts, alertData{LABEL: strs[0], USERS: strr})
						debugLog(v)
					}
				case 1:
					if len(strs) > 3 {
						pInt := -1
						switch strs[2] {
						case "R":
							pInt = 1
						case "RW":
							pInt = 2
						default:
							pInt = 0
						}

						if pInt > -1 {
							allows = append(allows, allowData{ID: strs[0], LABEL: strs[1], PERMISSION: pInt, REJECT: strs[3]})
							debugLog(v)
						}
					}
				case 2:
					if len(strs) > 3 {
						var strr []string

						for i := 2; i < len(strs); i++ {
							strr = append(strr, strs[i])
						}
						rejects = append(rejects, rejectData{LABEL: strs[0], ALERT: strs[1], COMMANDS: strr})
						debugLog(v)
					}
				case 3:
					pass := ""
					if plainpassword == true || Exists(strs[5]) == true {
						pass = strs[5]
					} else {
						passTmp, err := decrypt(strs[5], []byte(decryptstr))
						if err != nil {
							fmt.Println("WARN: not password decrypt!: ", strs[5])
							fmt.Println(err)
						}
						pass = passTmp
					}

					if checkRules == true {
						_, done, err := sshDo(strs[4], strs[2], pass, strs[3], "cd", 0)
						if done == false || err != nil {
							debugLog("RULE: " + strs[1] + " connect fail! " + strs[4] + " " + strs[5] + " " + pass + " " + strs[6])
						} else {
							debugLog("add RULE: " + strs[1] + " " + strs[4] + " " + strs[2] + " " + pass + " " + strs[3])
							hosts = append(hosts, hostsData{LABEL: strs[0], RULE: strs[1], HOST: strs[2], PORT: strs[3], USER: strs[4], PASSWD: pass, SHEBANG: strs[6]})
							cFlag = cFlag + 1
						}
					} else {
						debugLog("add RULE: " + strs[1] + " " + strs[4] + " " + strs[2] + " " + pass + " " + strs[3])
						hosts = append(hosts, hostsData{LABEL: strs[0], RULE: strs[1], HOST: strs[2], PORT: strs[3], USER: strs[4], PASSWD: pass, SHEBANG: strs[6]})
					}
				case 4:
					if len(strs) > 2 {
						var strr []string
						for i := 3; i < len(strs); i++ {
							strr = append(strr, strs[i])
						}
						convInt, err := strconv.Atoi(strs[2])
						if err == nil {
							udata = append(udata, userData{ID: strs[0], PWD: strs[1], HOST: convInt, ALIAS: strr})
						}
						debugLog(v)
					}
				}
			}
		}
	}
	if checkRules == true {
		if flag == 3 && cFlag == 0 {
			fmt.Println("all host not connect! check config!!")
			os.Exit(-1)
		}
	}
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func checkUsers(User string) int {
	for i := 0; i < len(udata); i++ {
		if udata[i].ID == User {
			return i
		}
	}

	udata = append(udata, userData{ID: User, HOST: -1, PWD: setHome(), ALIAS: nil})
	return len(udata) - 1
}

func setHome() string {
	// if len(os.Getenv("HOME")) == 0 {
	// 	return os.Getenv("HOMEPATH")
	// }
	// return os.Getenv("HOME")
	return "~/"
}

func checkHost(User string) bool {
	for i := 0; i < len(udata); i++ {
		if udata[i].ID == User {
			if udata[i].HOST == -1 {
				return false
			} else {
				return true
			}
		}
	}
	return false
}

func allowUser(User string) bool {
	for i := 0; i < len(allows); i++ {
		if allows[i].ID == User {
			return true
		}
	}
	return false
}

func JsonResponseToByte(status, message string) []byte {
	data := &responseData{Status: status, Message: message}
	outputJson, err := json.Marshal(data)
	if err != nil {
		return []byte(fmt.Sprintf("%s", err))
	}
	return []byte(outputJson)
}

func checkPreExecuter(sig chan string, User, Command string, hostInt int, channel string, api *slack.Client) (bool, string) {
	userInt := userCheck(User)
	if userInt == -1 {
		debugLog("Error: user not found. " + User + " " + Command)
		return false, User + ": user not found"
	}

	if len(Command) == 0 {
		debugLog("Error: command sring not include. " + User + " " + Command)
		return false, "command sring not include"
	}

	if checkRejct(udata[userInt].ID, Command) == true {
		fmt.Println("Error: include reject string. ", User, Command)
		strs := "include reject string!"
		if secAlert == true {
			strs = strs + "\n [Security Alert!] " + alertUsers()
		}
		return false, strs
	}

	if strings.Index(Command, "toSLACK=") == 0 {
		if allows[userInt].PERMISSION > 0 {
			if upload(hostInt, userInt, Command, channel, api) == false {
				return false, "<@" + udata[userInt].ID + "> file upload fail"
			} else {
				return true, "<@" + udata[userInt].ID + "> file upload success"
			}
		} else {
			strs := "<@" + udata[userInt].ID + "> not allow download"
			if secAlert == true {
				strs = strs + "\n [Security Alert!] " + alertUsers()
			}
			return false, strs
		}
	} else {
		go executer(sig, userInt, hostInt, Command, channel)
	}

	return true, ""
}

func checkRejct(ID, Command string) bool {
	uID := ""
	for i := 0; i < len(allows); i++ {
		if allows[i].ID == ID {
			uID = allows[i].REJECT
		}
	}
	if uID == "" {
		return true
	}

	rInt := 0
	for i := 0; i < len(rejects); i++ {
		if rejects[i].LABEL == uID {
			rInt = i + 1
		}
	}
	if rInt == 0 {
		return true
	}

	for i := 0; i < len(rejects[rInt-1].COMMANDS); i++ {
		if strings.Index(Command, rejects[rInt-1].COMMANDS[i]) != -1 {
			return true
		}
	}
	return false
}

func alertUsers() string {
	strs := ""
	for i := 0; i < len(alerts); i++ {
		for r := 0; r < len(alerts[i].USERS); r++ {
			switch alerts[i].USERS[r] {
			case "here":
				strs = strs + " <!here>"
			case "channel":
				strs = strs + " <!channnel>"
			case "everyone":
				strs = strs + " <!everyone>"
			default:
				strs = strs + " <@" + alerts[i].USERS[r] + ">"
			}
		}
	}
	return strs
}

func upload(hostInt, userInt int, Command, channel string, api *slack.Client) bool {
	strs := strings.Split(Command, "=")

	filepath := udata[userInt].PWD + "/" + strs[1]
	if scpDo(true, hostInt, filepath, strs[1]) == false {
		return false
	}

	if uploadToSlack(strs[1], channel, api) == false {
		return false
	}

	if err := os.Remove(strs[1]); err != nil {
		fmt.Println(err)
	}
	return true
}

func uploadToSlack(filename, channel string, api *slack.Client) bool {
	debugLog("uploading.. " + filename)

	debugLog("upload: " + filename + " to: " + channel)

	params := slack.FileUploadParameters{
		Title:    filename,
		File:     filename,
		Filetype: "binary",
		Channels: []string{channel},
	}

	file, err := api.UploadFile(params)
	if err != nil {
		fmt.Printf("%s\n", err)
		return false
	}

	fmt.Printf("upload! Name: %s, URL: %s\n", file.Name, file.URL, file.ID)
	return true
}

func userCheck(User string) int {
	for i := 0; i < len(udata); i++ {
		if udata[i].ID == User {
			return i
		}
	}
	return -1
}

func hostCheck(Host string) int {
	for i := 0; i < len(hosts); i++ {
		if hosts[i].RULE == Host {
			return i
		}
	}
	return -1
}

func executer(sig chan string, userInt, hostInt int, Command, channel string) {
	sshCommand := "cd " + udata[userInt].PWD + ";" + Command
	tmpFile := "tmp." + allows[userInt].ID
	if needSCP == true {
		writeFile(tmpFile+".bat", Command, userInt, true)

		scpFlag := false
		for i := 0; i < RETRY; i++ {
			if scpDo(false, hostInt, tmpFile+".bat", ".") == true {
				scpFlag = true
				break
			} else {
				break
			}
		}
		if scpFlag == false {
			sig <- channel + "\t"
			return
		}
		sshCommand = hosts[hostInt].SHEBANG + " " + tmpFile + ".bat"
	}

	var err error

	prompt := "[@" + botName + " " + udata[userInt].PWD + "]$ " + Command + "\n"
	done := false
	strs := ""
	for i := 0; i < RETRY; i++ {
		strs, done, err = sshDo(hosts[hostInt].USER, hosts[hostInt].HOST, hosts[hostInt].PASSWD, hosts[hostInt].PORT, sshCommand, sshTimeout)
		if done == true && len(strs) > 0 {
			break
		}
	}
	if done == false {
		sig <- channel + "\t"
		return
	}

	if strings.Index(Command, "pwd") == 0 {
		sig <- channel + "\t" + udata[userInt].ID + "\t" + prompt + "\t" + udata[userInt].PWD
		return
	}

	if err == nil && strings.Index(Command, "cd ") == 0 {
		stra := strings.Split(Command, "cd ")
		udata[userInt].PWD = stra[1]
		writeUsersData()
	}

	if len(strs) > 1 {
		sig <- channel + "\t" + udata[userInt].ID + "\t" + prompt + "\t" + convertChar(strs)
	} else {
		sig <- channel + "\t" + udata[userInt].ID + "\t" + prompt
	}
}

func convertChar(strs string) string {
	detector := chardet.NewTextDetector()
	result, err := detector.DetectBest([]byte(strs))
	if err == nil {
		if result.Charset == "Shift_JIS" {
			return sjis_to_utf8(strs)
		}
	}
	return strs
}

func sshDo(User, Host, Passwd, Port, Command string, timeouts int) (string, bool, error) {
	timeout := time.Duration(sshTimeout) * time.Second
	if timeouts != 0 {
		timeout = time.Duration(timeouts) * time.Second
	}

	ssh := &easyssh.MakeConfig{
		User:     User,
		Server:   Host,
		Password: Passwd,
		Port:     Port,
		Timeout:  timeout,
	}

	if Exists(Passwd) == true {
		ssh = &easyssh.MakeConfig{
			User:       User,
			Server:     Host,
			KeyPath:    Passwd,
			Port:       Port,
			Timeout:    timeout,
			Passphrase: "",
		}
	}

	debugLog("ssh: " + Command)

	stdout, stderr, done, err := ssh.Run(Command, timeout)

	debugLog("stdout is :" + stdout + ";   stderr is :" + stderr)

	if done == true {
		if len(stdout) > 0 {
			return stdout, done, err
		} else if len(stderr) > 0 {
			return stderr, done, err
		} else {
			return " ", done, err
		}
	}
	return " ", done, err
}

func scpDo(reverse bool, hostInt int, tmpFile, path string) bool {
	config := &ssh.ClientConfig{
		User:            hosts[hostInt].USER,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(hosts[hostInt].PASSWD),
		},
	}

	fmt.Println("scpDo " + hosts[hostInt].USER + " " + hosts[hostInt].PASSWD + " " + tmpFile + " " + path)

	if Exists(hosts[hostInt].PASSWD) == true {
		buf, err := ioutil.ReadFile(hosts[hostInt].PASSWD)
		if err != nil {
			fmt.Println(err)
			return false
		}
		key, err := ssh.ParsePrivateKey(buf)
		if err != nil {
			fmt.Println(err)
			return false
		}

		config = &ssh.ClientConfig{
			User:            hosts[hostInt].USER,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(key),
			},
		}
	}

	client, err := ssh.Dial("tcp", hosts[hostInt].HOST+":"+hosts[hostInt].PORT, config)
	if err != nil {
		fmt.Print(err.Error())
		return false
	}

	scp := new(scplib.SCPClient)
	scp.Permission = false // copy permission with scp flag
	scp.Connection = client

	if reverse == false {
		err = scp.PutFile([]string{tmpFile}, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to scp put: %s\n", err)
			return false
		}
	} else {
		err = scp.GetFile([]string{tmpFile}, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to scp put: %s\n", err)
			return false
		}
	}
	return true
}

// FYI: http://www.inanzzz.com/index.php/post/f3pe/data-encryption-and-decryption-with-a-secret-key-in-golang
// encrypt encrypts plain string with a secret key and returns encrypt string.
func encrypt(plainData string, secret []byte) (string, error) {
	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(crt.Reader, nonce); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plainData), nil)), nil
}

// decrypt decrypts encrypt string with a secret key and returns plain string.
func decrypt(encodedData string, secret []byte) (string, error) {
	encryptData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		return "", err
	}

	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(encryptData) < nonceSize {
		return "", err
	}

	nonce, cipherText := encryptData[:nonceSize], encryptData[nonceSize:]
	plainData, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainData), nil
}

func addSpace(strs string) string {
	for i := 0; len(strs) < 16; i++ {
		strs += "0"
	}
	return strs
}

//FYI: https://qiita.com/uchiko/items/1810ddacd23fd4d3c934
// ShiftJIS から UTF-8
func sjis_to_utf8(str string) string {
	ret, err := ioutil.ReadAll(transform.NewReader(strings.NewReader(str), japanese.ShiftJIS.NewDecoder()))
	if err != nil {
		fmt.Printf("Convert Error: %s\n", err)
		return ""
	}
	return string(ret)
}
