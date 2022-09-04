/*
 * Bringing true chatops with slack to your team.
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   BSD-2-Clause License, ISC License, BSD-3-Clause License
 */
package main

import (
	"bytes"
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
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"

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
	secAlert      bool
	debug         bool
	logging       bool
	delUpload     bool
	sshTimeout    int
	RETRY         int
	toFile        int
	alerts        []alertData
	allows        []allowData
	allowCmds     []allowCommandData
	rejects       []rejectData
	hosts         []hostsData
	udata         []userData
	botName       string
	autoRW        bool
	lockFile      string
	configFile    string
	admins        []string
	reports       string
	uploadtimeout int64
)

type alertData struct {
	LABEL string
	USERS []string
}

type allowData struct {
	ID         string
	LABEL      string
	PERMISSION int
	MODE       bool
	RULE       string
	EXPIRE     string
}

type rejectData struct {
	LABEL    string
	ALERT    string
	COMMANDS []string
}

type allowCommandData struct {
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
	_IDLookup := flag.Bool("idlookup", true, "[-idlookup=resolve to ID definition (true is enable)]")

	_autoRW := flag.Bool("auto", true, "[-auto=config auto read/write mode (true is enable)]")
	_lockFile := flag.String("lock", ".lock", "[-lock=lock file for auto read/write)]")
	_delUpload := flag.Bool("delUpload", false, "[-delUpload=file delete after upload (true is enable)]")
	_checkRules := flag.Bool("check", true, "[-check=check rules. if connect fail to not use rule. (true is enable)]")
	_loop := flag.Int("loop", 24, "[-loop=user check loop time (Hour). ]")
	_uploadtimeout := flag.Int64("uploadtimeout", 900, "[-uploadtimeout=Timeout time for uploading to Slack (Second). ]")

	flag.Parse()

	delUpload = bool(*_delUpload)
	secAlert = bool(*_secAlert)
	debug = bool(*_Debug)
	logging = bool(*_Logging)
	configFile = string(*_Config)
	RETRY = int(*_RETRY)
	sshTimeout = int(*_sshTimeout)
	toFile = int(*_TOFILE)
	botName = string(*_botName)
	uploadtimeout = int64(*_uploadtimeout)

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

	if Exists(configFile) == true {
		loadConfig(api, addSpace(*_decryptkey), *_plainpassword, *_checkRules, *_IDLookup)
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
						loadConfig(api, addSpace(*_decryptkey), *_plainpassword, false, *_IDLookup)
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

	go socketMode(sig, api, *_needSCP)

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
		time.Sleep(time.Hour * time.Duration(*_loop))
		usercheck(api)
	}
	os.Exit(0)
}

func usercheck(api *slack.Client) {
	const layout = "2006/01/02 15:04:05"
	t := time.Now()
	strs := "[" + t.Format(layout) + "]\n"
	for i := 0; i < len(allows); i++ {
		if expireCheck(allows[i].EXPIRE) == true {
			user, err := api.GetUserInfo(allows[i].ID)
			if err != nil {
				fmt.Printf("%s\n", err)
			} else {
				strs = strs + "User: " + allows[i].ID + "(" + user.Profile.RealName + " " + user.Profile.Email + ")" + " Not Expire: " + allows[i].EXPIRE + "\n"
				debugLog(strs)
			}

		} else {
			user, err := api.GetUserInfo(allows[i].ID)
			if err != nil {
				fmt.Printf("%s\n", err)
			} else {
				strs = strs + "User: " + allows[i].ID + "(" + user.Profile.RealName + " " + user.Profile.Email + ")" + " Expire: " + allows[i].EXPIRE + "\n"
				debugLog(strs)
			}
		}
	}

	_, _, err := api.PostMessage(reports, slack.MsgOptionText(strs, false))
	if err != nil {
		fmt.Printf("failed posting message: %v", err)
	}
}

func expireCheck(limit string) bool {
	if limit == "*" {
		return true
	}

	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		panic(err)
	}
	unixJST := time.Now().In(jst).Unix()
	t, _ := time.Parse("2006/01/02", limit)
	userLimit := t.In(jst).Unix()

	//u := strconv.FormatInt(userLimit, 10)
	//n := strconv.FormatInt(unixJST, 10)
	//debugLog("User: " + u + " System: " + n)

	if userLimit >= unixJST {
		return true
	}
	return false
}

func socketMode(sig chan string, api *slack.Client, needSCP bool) {
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
					case *slackevents.MessageEvent:
						if len(event.Text) > 1 && validMessage(api, event.Text, event.User, event.Channel) == true {
							//command := strings.Replace(event.Text, strings.Split(event.Text, " ")[0]+" ", "", 1)
							command := event.Text

							debugLog("socket call: " + event.User + " " + command)

							switch command {
							case "RULES":
								rules := returnRules(initUsers(event.User))

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
									stra := "Error: <@" + event.User + "> use no rules."
									if secAlert == true {
										stra = stra + "\n [Security Alert!] " + alertUsers()
									}
									_, _, err := api.PostMessage(event.Channel, slack.MsgOptionText(stra, false))
									if err != nil {
										fmt.Printf("failed posting message: %v", err)
									}
								}
							default:
								trueFalse := false
								text := ""
								splitStr := strings.Split(command, " ")
								adminChk := adminCommandCheck(event.User, splitStr[0])

								switch adminChk {
								case 0:
									debugLog("User: " + event.User + " call ADMIN Mode: " + command)
									trueFalse, text = adminCommand(command)
									if trueFalse == true {
										writeUsersData()
									}
								case 1:
									text = "<@" + event.User + "> not Allow ADMIN Mode."
									if secAlert == true {
										text = text + "\n [Security Alert!] " + alertUsers()
									}
								default:
									trueFalse, text = eventSwitcher(sig, event.User, command, event.Channel, api, needSCP)
								}

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

				text := ""
				if userInt == -1 {
					text = "ERROR: User not found.."
				} else {
					udata[userInt].HOST = hostCheck(ruleName, allows[retUser(callback.User.ID)].LABEL)

					text = "<@" + udata[userInt].ID + "> " + ruleName + " : host set"
					udata[userInt].PWD = setHome()
					writeUsersData()
				}

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

func validMessage(api *slack.Client, text, id, channnel string) bool {
	uFlag := false

	for _, user := range allows {
		if user.ID == id {
			uFlag = true
			break
		}
	}

	if uFlag == false {
		return false
	}

	command := strings.Split(text, " ")

	if strings.Index(text, "toSLACK=") == 0 {
		return true
	} else if strings.Index(text, "toSERVER=") == 0 {
		return true
	} else if strings.Index(text, "SETHOST=") == 0 {
		return true
	} else if strings.Index(text, "alias=") == 0 {
		return true
	} else if strings.Index(text, "RULES") == 0 {
		return true
	} else if strings.Index(text, "cd ") == 0 {
		return true
	}

	_, err := exec.Command("which", command[0]).Output()
	if err != nil {
		debugLog("command not found!: " + command[0])

		// Remove this comment if you wish to be notified when a command cannot be executed. But it is very annoying.
		//
		//_, _, err := api.PostMessage(channnel, slack.MsgOptionText("<@"+id+"> "+command[0]+": command not found!", false))
		//if err != nil {
		//	fmt.Printf("failed posting message: %v", err)
		//}
		return false
	}
	debugLog("commandValid: " + command[0])
	return true
}

func adminCommandCheck(user, command string) int {
	sFlag := false

	switch command {
	case "ALERT":
		sFlag = true
	case "ALLOWID":
		sFlag = true
	case "REJECT":
		sFlag = true
	case "HOSTS":
		sFlag = true
	case "ALLOW":
		sFlag = true
	case "ADMINS":
		sFlag = true
	case "REPORT":
		sFlag = true
	}

	for i := 0; i < len(admins); i++ {
		if admins[i] == user && sFlag == true {
			return 0
		}
	}

	if sFlag == true {
		return 1
	}

	return 2
}

func adminCommand(command string) (bool, string) {
	delFlag := false
	cmd := strings.Split(command, " ")
	param := strings.Split(cmd[1], ",")
	if len(param) < 1 {
		return false, "parameters not set!"
	}

	if param[0] == "DELETE" {
		delFlag = true
	}

	switch cmd[0] {
	case "ALERT":
		if delFlag == true {
			if len(param) != 2 {
				return false, "ALERT: delete parameter invalid. (!= 2)"
			}
			var tmpStr []alertData
			for i := 0; i < len(alerts); i++ {
				if alerts[i].LABEL != param[1] {
					tmpStr = append(tmpStr, alertData{LABEL: alerts[i].LABEL, USERS: alerts[i].USERS})
				}
			}
			alerts = tmpStr
			return true, "del ALERT: " + param[1]
		} else {
			for i := 0; i < len(alerts); i++ {
				if alerts[i].LABEL == param[0] {
					return false, "ALERT: parameter invalid. (same label exsits)"
				}
			}

			if len(param) < 2 {
				return false, "ALERT: parameter invalid. (< 2)"
			}
			var strr []string

			for i := 1; i < len(param); i++ {
				strr = append(strr, param[i])
			}
			alerts = append(alerts, alertData{LABEL: param[0], USERS: strr})
			return true, "add ALERT: " + param[0]
		}
	case "ALLOWID":
		if delFlag == true {
			if len(param) != 2 {
				return false, "ALLOWID: delete parameter invalid. (!= 2)"
			}
			var tmpStr []allowData
			for i := 0; i < len(allows); i++ {
				if allows[i].ID != param[1] {
					tmpStr = append(tmpStr, allowData{ID: allows[i].ID, LABEL: allows[i].LABEL, PERMISSION: allows[i].PERMISSION, MODE: allows[i].MODE, RULE: allows[i].RULE, EXPIRE: allows[i].EXPIRE})
				}
			}
			allows = tmpStr
			return true, "del ALLOWID: " + param[1]
		} else {
			for i := 0; i < len(allows); i++ {
				if allows[i].ID == param[0] {
					return false, "ALLOWID: parameter invalid. (same label exsits)"
				}
			}

			if len(param) != 6 {
				return false, "ALLOWID: parameter invalid. (!= 6)"
			}
			pInt := 0
			switch param[2] {
			case "R":
				pInt = 1
			case "RW":
				pInt = 2
			}

			mode := false
			switch param[3] {
			case "allow":
				mode = true
			}

			allows = append(allows, allowData{ID: param[0], LABEL: param[1], PERMISSION: pInt, MODE: mode, RULE: param[4], EXPIRE: param[5]})
			return true, "add ALLOWID: " + param[0]
		}
	case "REJECT":
		if delFlag == true {
			if len(param) != 2 {
				return false, "REJECT: delete parameter invalid. (!= 2)"
			}
			var tmpStr []rejectData
			for i := 0; i < len(rejects); i++ {
				if rejects[i].LABEL != param[1] {
					tmpStr = append(tmpStr, rejectData{LABEL: rejects[i].LABEL, ALERT: rejects[i].ALERT, COMMANDS: rejects[i].COMMANDS})
				}
			}
			rejects = tmpStr
			return true, "del REJECT: " + param[1]
		} else {
			for i := 0; i < len(rejects); i++ {
				if rejects[i].LABEL == param[0] {
					return false, "REJECT: parameter invalid. (same label exsits)"
				}
			}

			if len(param) < 3 {
				return false, "REJECT: parameter invalid. (< 3)"
			}
			var strr []string

			for i := 2; i < len(param); i++ {
				strr = append(strr, param[i])
			}
			rejects = append(rejects, rejectData{LABEL: param[0], ALERT: param[1], COMMANDS: strr})
			return true, "add REJECT: " + param[0]
		}
	case "HOSTS":
		if delFlag == true {
			if len(param) != 2 {
				return false, "HOSTS: delete parameter invalid. (!= 2)"
			}
			var tmpStr []hostsData
			for i := 0; i < len(hosts); i++ {
				if hosts[i].LABEL != param[1] {
					tmpStr = append(tmpStr, hostsData{LABEL: hosts[i].LABEL, RULE: hosts[i].RULE, HOST: hosts[i].HOST, PORT: hosts[i].PORT, USER: hosts[i].USER, PASSWD: hosts[i].PASSWD, SHEBANG: hosts[i].SHEBANG})
				}
			}
			hosts = tmpStr
			return true, "del HOSTS: " + param[1]
		} else {
			for i := 0; i < len(hosts); i++ {
				if hosts[i].LABEL == param[0] {
					return false, "HOSTS: parameter invalid. (same label exsits)"
				}
			}

			if len(param) != 7 {
				return false, "HOSTS: parameter invalid. (!= 7)"
			}
			hosts = append(hosts, hostsData{LABEL: param[0], RULE: param[1], HOST: param[2], PORT: param[3], USER: param[4], PASSWD: param[5], SHEBANG: param[6]})
			return true, "add HOSTS: " + param[0]
		}
	case "ALLOW":
		if delFlag == true {
			if len(param) != 2 {
				return false, "ALLOW: delete parameter invalid. (!= 2)"
			}
			var tmpStr []allowCommandData
			for i := 0; i < len(allowCmds); i++ {
				if allowCmds[i].LABEL != param[1] {
					tmpStr = append(tmpStr, allowCommandData{LABEL: allowCmds[i].LABEL, ALERT: allowCmds[i].ALERT, COMMANDS: allowCmds[i].COMMANDS})
				}
			}
			allowCmds = tmpStr
			return true, "del ALLOW: " + param[1]
		} else {
			for i := 0; i < len(allowCmds); i++ {
				if allowCmds[i].LABEL == param[0] {
					return false, "ALLOW: parameter invalid. (same label exsits)"
				}
			}

			if len(param) < 3 {
				return false, "ALLOW: parameter invalid. (< 3)"
			}
			var strr []string

			for i := 2; i < len(param); i++ {
				strr = append(strr, param[i])
			}
			allowCmds = append(allowCmds, allowCommandData{LABEL: param[0], ALERT: param[1], COMMANDS: strr})
			return true, "add ALLOW: " + param[0]
		}
	case "ADMINS":
		if delFlag == true {
			if len(param) != 2 {
				return false, "ADMINS: delete parameter invalid. (!= 2)"
			}
			var tmpStr []string
			for i := 0; i < len(admins); i++ {
				if admins[i] != param[1] {
					tmpStr = append(tmpStr, admins[i])
				}
			}
			admins = tmpStr
			return true, "del ADMINS: " + param[1]
		} else {
			for i := 0; i < len(admins); i++ {
				if admins[i] == param[0] {
					return false, "ADMINS: parameter invalid. (same label exsits)"
				}
			}

			if len(param) != 1 {
				return false, "ALLOW: parameter invalid. (!= 1)"
			}
			admins = append(admins, param[0])
			return true, "add ADMINS: " + param[0]
		}
	case "REPORT":
		if len(param) != 1 {
			return false, "REPORT: parameter invalid. (!= 1)"
		}
		reports = param[0]
		return true, "report channnel changed"
	}
	return false, "internal failure.."
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

func eventSwitcher(sig chan string, User, Command, channel string, api *slack.Client, needSCP bool) (bool, string) {
	userInt := checkUsers(User)
	if userInt == -1 {
		return false, "ERROR: User not found.."
	}

	// for debug
	// udata[userInt].HOST = 0
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
			if checkMode(udata[userInt].ID) == false {
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
				data = "<@" + udata[userInt].ID + "> : allow mode, alias not use!"
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
			hostInt := hostCheck(stra[1], allows[retUser(User)].LABEL)
			if hostInt == -2 {
				debugLog("Error: host not allow. " + User + " " + Command)

				trueFalse = false
				data = "<@" + udata[userInt].ID + "> " + stra[1] + " : host not allow"
				if secAlert == true {
					data = data + "\n [Security Alert!] " + alertUsers()
				}
			} else if hostInt == -1 {
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

			path := ""
			if stra[1] == "." {
				path = "."
			} else if strings.Index(stra[1], "/") == 0 {
				path = stra[1] + "/"
			} else {
				path = udata[userInt].PWD + "/" + stra[1] + "/"
			}

			trueFalse, data = uploadFile(userInt, path, api)
		} else {
			trueFalse = false
			data = "<@" + udata[userInt].ID + "> : not allow upload"
			if secAlert == true {
				data = data + "\n [Security Alert!] " + alertUsers()
			}
		}
	} else if strings.Index(Command, "toSLACK=") == 0 && udata[userInt].HOST != -1 {
		if allows[userInt].PERMISSION > 0 {
			stra := strings.Split(Command, "toSLACK=")

			if upload(udata[userInt].HOST, userInt, stra[1], channel, api) == false {
				data = "<@" + udata[userInt].ID + "> file upload fail"
				trueFalse = false
			} else {
				data = "<@" + udata[userInt].ID + "> file upload success"
				trueFalse = true
			}
		} else {
			trueFalse = false
			data = "<@" + udata[userInt].ID + "> : not allow download"
			if secAlert == true {
				data = data + "\n [Security Alert!] " + alertUsers()
			}
		}
	} else {
		if checkHost(User) == true {
			Command = replaceAlias(userInt, Command)
			trueFalse, data = checkPreExecuter(sig, User, Command, udata[userInt].HOST, channel, api, needSCP)
		} else {
			trueFalse = false
			data = "<@" + udata[userInt].ID + "> " + Command + ": host not set"
		}
	}
	return trueFalse, data
}

func checkMode(ID string) bool {
	for i := 0; i < len(allows); i++ {
		if allows[i].ID == ID {
			return allows[i].MODE
		}
	}
	return true
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

	if scpDo(false, udata[userInt].HOST, files[0].Name, path) == false {
		return false, "file not scp: " + files[0].Name
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
			PERM := "NO"
			switch allows[i].PERMISSION {
			case 1:
				PERM = "R"
			case 2:
				PERM = "RW"
			}

			MODE := "reject"
			switch allows[i].MODE {
			case true:
				MODE = "allow"
			}

			_, err = file.WriteString(allows[i].ID + "\t" + allows[i].LABEL + "\t" + PERM + "\t" + MODE + "\t" + allows[i].RULE + "\t" + allows[i].EXPIRE + "\n")
		}

		_, err = file.WriteString("[REJECT]\n")
		for i := 0; i < len(rejects); i++ {
			_, err = file.WriteString(rejects[i].LABEL + "\t" + rejects[i].ALERT + "\t")
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

		_, err = file.WriteString("[ALLOW]\n")
		for i := 0; i < len(allowCmds); i++ {
			_, err = file.WriteString(allowCmds[i].LABEL + "\t" + allowCmds[i].ALERT + "\t")
			for r := 0; r < len(allowCmds[i].COMMANDS); r++ {
				if r == 0 {
					_, err = file.WriteString(allowCmds[i].COMMANDS[r])
				} else {
					_, err = file.WriteString("\t" + allowCmds[i].COMMANDS[r])
				}
			}
			_, err = file.WriteString("\n")
		}

		_, err = file.WriteString("[ADMINS]\n")
		for i := 0; i < len(admins); i++ {
			_, err = file.WriteString(admins[i] + "\n")
		}

		_, err = file.WriteString("[REPORT]\n")
		_, err = file.WriteString(reports + "\n")

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
	const layout2 = "2006/01/02 15:04:05"
	t := time.Now()
	filename := botName + "_" + t.Format(layout) + ".log"
	logHead := "[" + t.Format(layout2) + "] "

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
	fmt.Fprintln(file, logHead+message)
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

func loadConfig(api *slack.Client, decryptstr string, plainpassword bool, checkRules, idlookup bool) {
	loadOptions := ini.LoadOptions{}
	loadOptions.UnparseableSections = []string{"ALERT", "ALLOWID", "REJECT", "HOSTS", "USERS", "ALLOW", "USERS", "ALLOW", "ADMINS", "REPORT"}

	cfg, err := ini.LoadSources(loadOptions, configFile)
	if err != nil {
		fmt.Printf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	usersMap := map[string]string{}

	if idlookup == true {
		users, err := api.GetUsers()
		if err == nil {
			for _, user := range users {
				debugLog("UserIDs: " + user.ID + " " + user.Name)
				usersMap[user.Name] = user.ID
			}
		}
	}

	alerts = nil
	allows = nil
	rejects = nil
	hosts = nil
	udata = nil
	allowCmds = nil
	admins = nil
	reports = ""

	setStructs("ALERT", cfg.Section("ALERT").Body(), 0, "", false, false, idlookup, usersMap)
	setStructs("ALLOWID", cfg.Section("ALLOWID").Body(), 1, "", false, false, idlookup, usersMap)
	setStructs("REJECT", cfg.Section("REJECT").Body(), 2, "", false, false, idlookup, usersMap)
	setStructs("HOSTS", cfg.Section("HOSTS").Body(), 3, decryptstr, plainpassword, checkRules, idlookup, usersMap)
	setStructs("USERS", cfg.Section("USERS").Body(), 4, "", false, false, idlookup, usersMap)
	setStructs("ALLOW", cfg.Section("ALLOW").Body(), 5, "", false, false, idlookup, usersMap)
	setStructs("ADMINS", cfg.Section("ADMINS").Body(), 6, "", false, false, idlookup, usersMap)
	setStructs("REPORT", cfg.Section("REPORT").Body(), 7, "", false, false, idlookup, usersMap)
}

func setStructs(configType, datas string, flag int, decryptstr string, plainpassword, checkRules, idlookup bool, users map[string]string) {
	cFlag := 0
	debugLog(" -- " + configType + " --")

	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if len(v) > 0 {
			if strings.Index(v, "\t") != -1 && flag != 6 && flag != 7 {
				strs := strings.Split(v, "\t")

				switch flag {
				case 0:
					if len(strs) > 1 {
						var strr []string

						for i := 1; i < len(strs); i++ {
							strr = append(strr, setUserStr(idlookup, users, strs[i]))
						}
						alerts = append(alerts, alertData{LABEL: strs[0], USERS: strr})
						debugLog(v)
					}
				case 1:
					if len(strs) == 6 {
						pInt := 0
						switch strs[2] {
						case "R":
							pInt = 1
						case "RW":
							pInt = 2
						}

						mode := false
						switch strs[3] {
						case "allow":
							mode = true
						}

						allows = append(allows, allowData{ID: setUserStr(idlookup, users, strs[0]), LABEL: strs[1], PERMISSION: pInt, MODE: mode, RULE: strs[4], EXPIRE: strs[5]})
						debugLog(v)
					}
				case 2:
					if len(strs) > 2 {
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
							debugLog("RULE: " + strs[0] + " connect fail! " + strs[3] + " " + strs[4] + " " + pass + " " + strs[5])
						} else {
							debugLog("add RULE: " + strs[0] + " " + strs[3] + " " + strs[1] + " " + pass + " " + strs[2])
							hosts = append(hosts, hostsData{LABEL: strs[0], RULE: strs[1], HOST: strs[2], PORT: strs[3], USER: strs[4], PASSWD: pass, SHEBANG: strs[6]})
							cFlag = cFlag + 1
						}
					} else {
						debugLog("add RULE: " + strs[1] + " " + strs[4] + " " + strs[2] + " " + pass + " " + strs[3] + " " + strs[6])
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
				case 5:
					if len(strs) > 2 {
						var strr []string

						for i := 2; i < len(strs); i++ {
							strr = append(strr, strs[i])
						}
						allowCmds = append(allowCmds, allowCommandData{LABEL: strs[0], ALERT: strs[1], COMMANDS: strr})
						debugLog(v)
					}
				}
			} else if flag == 6 {
				admins = append(admins, v)
				debugLog(v)
			} else if flag == 7 {
				reports = v
				debugLog(v)
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

func setUserStr(IDLookup bool, users map[string]string, key string) string {
	if IDLookup == true {
		us, ok := users[key]
		if ok == true {
			debugLog("Resove User: " + key + " -> " + us)
			return us
		}
	}
	debugLog("No Resolv:" + key)
	return key
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func initUsers(User string) int {
	usertNum := 0

	for i := 0; i < len(allows); i++ {
		if allows[i].ID == User {
			usertNum = i
		}
	}

	if usertNum == 0 {
		return -1
	}

	udata = append(udata, userData{ID: User, HOST: -1, PWD: setHome(), ALIAS: nil})
	return usertNum
}

func retUser(User string) int {
	for i := 0; i < len(allows); i++ {
		if allows[i].ID == User {
			return i
		}
	}

	return -1
}

func checkUsers(User string) int {
	for i := 0; i < len(udata); i++ {
		if udata[i].ID == User {
			return i
		}
	}
	return -1
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

func checkPreExecuter(sig chan string, User, Command string, hostInt int, channel string, api *slack.Client, needSCP bool) (bool, string) {
	userInt := userRuleCheck(User)
	if userInt == -1 {
		debugLog("Error: user not found. " + User + " " + Command)
		return false, User + ": user not found"
	}

	if len(Command) == 0 {
		debugLog("Error: command sring not include. " + User + " " + Command)
		return false, "command sring not include"
	}

	debugLog("Expire check: " + User + " Expire: " + allows[userInt].EXPIRE)
	if expireCheck(allows[userInt].EXPIRE) == false {
		return false, "id expire " + allows[userInt].EXPIRE
	}

	if checkRejct(allows[userInt].ID, Command) == true {
		fmt.Println("Error: include reject string. ", User, Command)
		strs := "include reject string!"
		if secAlert == true {
			strs = strs + "\n [Security Alert!] " + alertUsers()
		}
		return false, strs
	}

	userInt = userCheck(User)

	go executer(sig, userInt, hostInt, Command, channel, needSCP)

	return true, ""
}

func checkRejct(ID, Command string) bool {
	sID := 0
	uID := ""
	for i := 0; i < len(allows); i++ {
		if allows[i].ID == ID {
			uID = allows[i].RULE
			sID = i
		}
	}
	if uID == "" {
		return true
	}

	switch allows[sID].MODE {
	case true:
		//alllow mode
		aInt := 0
		for i := 0; i < len(allowCmds); i++ {
			if allowCmds[i].LABEL == uID {
				aInt = i + 1
			}
		}
		if aInt == 0 {
			return true
		}

		for i := 0; i < len(allowCmds[aInt-1].COMMANDS); i++ {
			if strings.Index(Command, allowCmds[aInt-1].COMMANDS[i]+" ") == 0 || strings.Index(Command, allowCmds[aInt-1].COMMANDS[i]) == 0 {
				if checkPipe(Command) == true {
					return false
				}
			}
		}
		return true
	default:
		//reject mode
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
	}

	return false
}

func checkPipe(command string) bool {
	if strings.Index(command, ">") != -1 {
		return false
	}
	if strings.Index(command, "<") != -1 {
		return false
	}
	if strings.Index(command, "|") != -1 {
		return false
	}
	if strings.Index(command, "&") != -1 {
		return false
	}
	if strings.Index(command, ";") != -1 {
		return false
	}
	debugLog(command + " include pipe!")

	return true
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
	filepath := ""
	if strings.Index(Command, "/") == 0 {
		filepath = Command
		stra := strings.Split(Command, "/")
		Command = stra[len(stra)-1]
	} else {
		filepath = udata[userInt].PWD + "/" + Command
	}
	debugLog("filepath: " + filepath)

	if scpDo(true, hostInt, filepath, Command) == false {
		return false
	}

	if uploadToSlack(Command, channel, api) == false {
		return false
	}

	time.Sleep(60 * time.Second)

	fmt.Println("DELETE" + Command)
	if err := os.Remove(Command); err != nil {
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

func userRuleCheck(User string) int {
	for i := 0; i < len(allows); i++ {
		if allows[i].ID == User {
			return i
		}
	}
	return -1
}

func userCheck(User string) int {
	for i := 0; i < len(udata); i++ {
		if udata[i].ID == User {
			return i
		}
	}
	return -1
}

func hostCheck(Host, uLabel string) int {
	rFlag := false
	for i := 0; i < len(hosts); i++ {
		if hosts[i].RULE == Host {
			if hosts[i].LABEL == uLabel {
				return i
			}
			rFlag = true
		}
	}
	if rFlag == false {
		return -2
	}
	return -1
}

func lookup(host int) string {
	return hosts[host].RULE
}

func executer(sig chan string, userInt, hostInt int, Command, channel string, needSCP bool) {
	prompt := "[@" + lookup(udata[userInt].HOST) + " " + udata[userInt].PWD + "]$ " + Command + "\n"
	done := false
	strs := ""
	dFlag := false

	if strings.Index(Command, "pwd") == 0 {
		sig <- channel + "\t" + udata[userInt].ID + "\t" + prompt + "\t" + udata[userInt].PWD
		return
	}

	sshCommand := "cd " + udata[userInt].PWD + ";" + Command
	tmpFile := "tmp." + allows[userInt].ID

	if Command != "cd /" {
		if Command[len(Command)-1] == 47 {
			Command = Command[:len(Command)-1]
		}
	}

	var stra []string
	if strings.Index(Command, "cd ") == 0 {
		dFlag = true
		stra = strings.Split(Command, "cd ")
		if strings.Index(stra[1], "/") == 0 {
			sshCommand = "cd " + stra[1] + " ; pwd"
		} else {
			sshCommand = "cd " + udata[userInt].PWD + "/" + stra[1] + " ; pwd"
		}
	} else if Command[0] == byte('#') && len(Command) > 1 {
		Command = Command[1:]
		debugLog("# is force no scp mode: " + Command)
	} else if needSCP == true {
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
		sshCommand = hosts[hostInt].SHEBANG + " ~/" + tmpFile + ".bat"
	}

	for i := 0; i < RETRY; i++ {
		strs, done, _ = sshDo(hosts[hostInt].USER, hosts[hostInt].HOST, hosts[hostInt].PASSWD, hosts[hostInt].PORT, sshCommand, sshTimeout)
		if done == true {
			break
		}
	}

	if dFlag == true && done == true {
		udata[userInt].PWD = strings.TrimRight(strs, "\n")

		sig <- channel + "\t" + udata[userInt].ID + "\t" + prompt + "\t" + udata[userInt].PWD
		writeUsersData()
		return
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

	config := &ssh.ClientConfig{
		User:            User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(Passwd),
		},
		Timeout: timeout,
	}

	if Exists(Passwd) == true {
		buf, err := ioutil.ReadFile(Passwd)
		if err != nil {
			fmt.Println(err)
			return "", false, err
		}
		key, err := ssh.ParsePrivateKey(buf)
		if err != nil {
			fmt.Println(err)
			return "", false, err
		}
		config = &ssh.ClientConfig{
			User:            User,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(key),
			},
			Timeout: timeout,
		}
	}

	debugLog("ssh: " + Command)

	conn, err := ssh.Dial("tcp", Host+":"+Port, config)
	if err != nil {
		fmt.Println(err)
		return "", false, err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		fmt.Println(err)
		return "", false, err
	}
	defer session.Close()

	var b, e bytes.Buffer
	session.Stdout = &b
	session.Stderr = &e

	debugLog("stdout is :" + b.String() + ";   stderr is :" + e.String())

	if err := session.Run(Command); err != nil {
		return e.String(), false, err
	}

	return b.String(), true, err
}

func scpDo(reverse bool, hostInt int, tmpFile, path string) bool {
	config := &ssh.ClientConfig{
		User:            hosts[hostInt].USER,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(hosts[hostInt].PASSWD),
		},
		Timeout: time.Duration(uploadtimeout) * time.Second,
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
			Timeout: time.Duration(uploadtimeout) * time.Second,
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
			scp.Connection.Close()
			return false
		}
	} else {
		err = scp.GetFile([]string{tmpFile}, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to scp put: %s\n", err)
			scp.Connection.Close()
			return false
		}
	}
	scp.Connection.Close()
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
