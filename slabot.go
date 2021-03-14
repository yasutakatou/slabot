/*
 * Bringing true chatops with slack to your team.
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   BSD-2-Clause License, ISC License
 */
package main

import (
	"crypto/aes"
	"crypto/cipher"
	crt "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/appleboy/easyssh-proxy"
	"github.com/fsnotify/fsnotify"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/ini.v1"
)

var (
	debug   bool
	logging bool
	needSCP bool
	RETRY   int
	toFile  int
	users   []string
	rejects []string
	hosts   []hostsData
	udata   []userData
	botName string
)

type userData struct {
	ID    string
	PWD   string
	HOST  int
	ALIAS []string
}

type hostsData struct {
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
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_Logging := flag.Bool("log", false, "[-log=logging mode (true is enable)]")
	_Config := flag.String("config", ".slabot", "[-config=config file)]")
	_Rest := flag.Bool("rest", false, "[-rest=normal slack mode (true is enable)]")
	_Api := flag.Bool("api", false, "[-api=api mode (true is enable)]")
	_cert := flag.String("cert", "localhost.pem", "[-cert=ssl_certificate file path (if you don't use https, haven't to use this option)]")
	_key := flag.String("key", "localhost-key.pem", "[-key=ssl_certificate_key file path (if you don't use https, haven't to use this option)]")
	_port := flag.String("port", "8080", "[-port=port number]")
	_needSCP := flag.Bool("scp", true, "[-scp=need scp mode (true is enable)]")
	_RETRY := flag.Int("retry", 10, "[-retry=retry counts.]")
	_plainpassword := flag.Bool("plainpassword", false, "[-plainpassword=use plain text password (true is enable)]")
	_decryptkey := flag.String("decrypt", "", "[-decrypt=password decrypt key string]")
	_encrypt := flag.String("encrypt", "", "[-encrypt=password encrypt key string ex) pass:key (JUST ENCRYPT EXIT!)]")
	_TOFILE := flag.Int("toFile", 20, "[-toFile=if output over this value. be file.]")
	_botName := flag.String("bot", "slabot", "[-bot=slack bot name (@ + name)]")

	flag.Parse()

	needSCP = bool(*_needSCP)
	debug = bool(*_Debug)
	logging = bool(*_Logging)
	Config := string(*_Config)
	RETRY = int(*_RETRY)
	toFile = int(*_TOFILE)
	botName = string(*_botName)

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

	if Exists(Config) == true {
		loadConfig(Config, addSpace(*_decryptkey), *_plainpassword)
	} else {
		fmt.Printf("Fail to read config file: %v\n", Config)
		os.Exit(1)
	}

	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case <-watcher.Events:
				loadConfig(Config, addSpace(*_decryptkey), *_plainpassword)
			case <-watcher.Errors:
				fmt.Println("ERROR", err)
			}
		}
	}()

	if err := watcher.Add(Config); err != nil {
		fmt.Println("ERROR", err)
	}

	if *_Api == true {
		http.HandleFunc("/api", apiHandler)
		go func() {
			err := http.ListenAndServeTLS(":"+string(*_port), string(*_cert), string(*_key), nil)
			if err != nil {
				log.Fatal("ListenAndServeTLS: ", err)
			}
		}()
	} else if *_Rest == true {
		http.HandleFunc("/slack/events", slackHandler)
		go func() {
			if err := http.ListenAndServe(":"+string(*_port), nil); err != nil {
				log.Fatal(err)
			}
		}()
	} else {
		socketMode()
	}

	for {
		_, ip, err := getIFandIP()
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("source ip: ", ip, " port: ", string(*_port)+" Exit: Ctrl+c")
		}
		time.Sleep(time.Second * 3)
	}
	os.Exit(0)
}

func socketMode() {
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

							trueFalse, text := eventSwitcher(event.User, command, event.Channel)

							if trueFalse == false {
								text = "Error: " + text
							}

							_, _, err := api.PostMessage(event.Channel, slack.MsgOptionText(text, false))
							if err != nil {
								fmt.Printf("failed posting message: %v", err)
							}
						}
					case *slackevents.MemberJoinedChannelEvent:
						fmt.Printf("user %q joined to channel %q", event.User, event.Channel)
					}
				default:
					client.Debugf("unsupported Events API event received")
				}
			default:
				fmt.Fprintf(os.Stderr, "Unexpected event type received: %s\n", evt.Type)
			}
		}
	}()
	client.Run()
}

func slackHandler(w http.ResponseWriter, r *http.Request) {
	api := slack.New(os.Getenv("SLACK_BOT_TOKEN"))

	verifier, err := slack.NewSecretsVerifier(r.Header, os.Getenv("SLACK_SIGNING_SECRET"))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bodyReader := io.TeeReader(r.Body, &verifier)
	body, err := ioutil.ReadAll(bodyReader)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := verifier.Ensure(); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	eventsAPIEvent, err := slackevents.ParseEvent(json.RawMessage(body), slackevents.OptionNoVerifyToken())
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch eventsAPIEvent.Type {
	case slackevents.URLVerification:
		var res *slackevents.ChallengeResponse
		if err := json.Unmarshal(body, &res); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(res.Challenge)); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case slackevents.CallbackEvent:
		innerEvent := eventsAPIEvent.InnerEvent
		switch event := innerEvent.Data.(type) {
		case *slackevents.AppMentionEvent:
			message := strings.Split(event.Text, " ")
			if len(message) < 2 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			command := strings.Replace(event.Text, message[0]+" ", "", 1)

			debugLog("slack call: " + r.RemoteAddr + " " + r.URL.Path + " " + event.User + " " + command)

			trueFalse, text := eventSwitcher(event.User, command, event.Channel)

			if trueFalse == false {
				text = "Error: " + text
			}

			if _, _, err := api.PostMessage(event.Channel, slack.MsgOptionText(text, false)); err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
	}
}

func returnAlias(userInt int) string {
	strs := ""
	for i := 0; i < len(udata[userInt].ALIAS); i++ {
		s := strconv.Itoa(i + 1)
		strs = strs + "[" + s + "] " + udata[userInt].ALIAS[i] + "\n"
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

func eventSwitcher(User, Command, channel string) (bool, string) {
	userInt := checkUsers(User)

	// for debug
	// udata[userInt].HOST = 0
	// for debug

	trueFalse := false
	data := ""

	debugLog("User: " + User + " Command: " + Command)

	if allowUser(User) == false {
		trueFalse = false
		data = User + " : user not allow"
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
			} else {
				Command := strings.Replace(Command, "alias ", "", 1)
				udata[userInt].ALIAS = append(udata[userInt].ALIAS, Command)
				trueFalse = true
				data = "<@" + udata[userInt].ID + "> " + Command + " : alias set"
			}
		} else {
			trueFalse = false
			data = "<@" + udata[userInt].ID + "> " + Command + " : alias set fail"
		}
	} else if strings.Index(Command, "SETHOST=") == 0 {
		stra := strings.Split(Command, "SETHOST=")
		hostInt := hostCheck(stra[1])
		if hostInt == -1 {
			debugLog("Error: host not found. " + User + " " + Command)

			trueFalse = false
			data = "<@" + udata[userInt].ID + "> " + stra[1] + " : host not found"
		} else {
			fmt.Println(udata[userInt].HOST)
			fmt.Println(hostInt)
			udata[userInt].HOST = hostInt
			fmt.Println(udata[userInt].HOST)

			trueFalse = true
			data = "<@" + udata[userInt].ID + "> " + stra[1] + " : host set"
		}
	} else {
		if checkHost(User) == true {
			Command = replaceAlias(userInt, Command)
			trueFalse, data = checkPreExecuter(User, Command, udata[userInt].HOST, channel)
		} else {
			trueFalse = false
			data = "<@" + udata[userInt].ID + "> " + Command + ": host not set"
		}
	}
	return trueFalse, data
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

func loadConfig(filename, decryptstr string, plainpassword bool) {
	loadOptions := ini.LoadOptions{}
	loadOptions.UnparseableSections = []string{"ALLOWID", "REJECT", "HOSTS"}

	cfg, err := ini.LoadSources(loadOptions, filename)
	if err != nil {
		fmt.Printf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	users = nil
	rejects = nil
	hosts = nil

	setSingleConfigStrs(&users, "ALLOWID", cfg.Section("ALLOWID").Body())
	setSingleConfigStrs(&rejects, "REJECT", cfg.Section("REJECT").Body())
	setSingleConfigHosts(&hosts, "HOSTS", cfg.Section("HOSTS").Body(), decryptstr, plainpassword)
}

func setSingleConfigStrs(config *[]string, configType, datas string) {
	debugLog(" -- " + configType + " --")

	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if len(v) > 0 {
			*config = append(*config, v)
		}
		debugLog(v)
	}
}

func setSingleConfigHosts(config *[]hostsData, configType, datas, decryptstr string, plainpassword bool) {
	debugLog(" -- " + configType + " --")

	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if len(v) > 0 {
			if strings.Index(v, ",") != -1 {
				strs := strings.Split(v, ",")
				pass := ""
				if plainpassword == true || Exists(strs[4]) == true {
					pass = strs[4]
				} else {
					passTmp, err := decrypt(strs[4], []byte(decryptstr))
					if err != nil {
						fmt.Println("ERROR: not password decrypt!")
						fmt.Println(err)
						os.Exit(1)
					}
					pass = passTmp
				}
				*config = append(*config, hostsData{RULE: strs[0], HOST: strs[1], PORT: strs[2], USER: strs[3], PASSWD: pass, SHEBANG: strs[5]})

				debugLog(strs[0] + " " + strs[1] + " " + strs[2] + " " + strs[3] + " " + pass + " " + strs[5])
			}
		}
	}
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// FYI: https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func getIFandIP() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return iface.Name, ip.String(), nil
		}
	}
	return "", "", errors.New("are you connected to the network?")
}

func checkUsers(User string) int {
	for i := 0; i < len(udata); i++ {
		if udata[i].ID == User {
			return i
		}
	}

	udata = append(udata, userData{ID: User, HOST: -1, PWD: os.Getenv("HOME"), ALIAS: nil})
	return len(udata) - 1
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
	for i := 0; i < len(users); i++ {
		if users[i] == User {
			return true
		}
	}
	return false
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	d := json.NewDecoder(r.Body)
	p := &receiveData{}
	err := d.Decode(p)
	if err != nil {
		w.Write(JsonResponseToByte("Error", "internal server error"))
		return
	}

	debugLog("api call: " + r.RemoteAddr + " " + r.URL.Path + " " + p.User + " " + p.Command)

	data := responseData{Status: "", Message: ""}

	trueFalse, text := eventSwitcher(p.User, p.Command, "")

	if trueFalse == true {
		data = responseData{Status: "Success", Message: text}
	} else {
		data = responseData{Status: "Error", Message: text}
	}

	outputJson, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	w.Write(outputJson)
}

func JsonResponseToByte(status, message string) []byte {
	data := &responseData{Status: status, Message: message}
	outputJson, err := json.Marshal(data)
	if err != nil {
		return []byte(fmt.Sprintf("%s", err))
	}
	return []byte(outputJson)
}

func checkPreExecuter(User, Command string, hostInt int, channel string) (bool, string) {
	userInt := userCheck(User)
	if userInt == -1 {
		debugLog("Error: user not found. " + User + " " + Command)
		return false, User + ": user not found"
	}

	if len(Command) == 0 {
		debugLog("Error: command sring not include. " + User + " " + Command)
		return false, "command sring not include"
	}

	for i := 0; i < len(rejects); i++ {
		if strings.Index(Command, rejects[i]) != -1 {
			fmt.Println("Error: include reject string. ", User, Command)
			return false, "include reject string!"
		}
	}

	if strings.Index(Command, "UPLOAD=") == 0 {
		if upload(userInt, Command, channel) == false {
			return false, "<@" + udata[userInt].ID + "> file upload fail"
		} else {
			return true, "<@" + udata[userInt].ID + "> alfile upload success"
		}
	} else {
		strs := executer(userInt, hostInt, Command, channel)
		if len(strs) == 0 {
			return false, "command not execute"
		} else {
			return true, strs
		}
	}

	return true, User + ":" + Command
}

func upload(userInt int, Command, channel string) bool {
	strs := strings.Split(Command, "=")

	filepath := udata[userInt].PWD + "/" + strs[1]
	if Exists(filepath) == false {
		filepath = udata[userInt].PWD + strs[1]
		if Exists(filepath) == false {
			debugLog("upload fail " + filepath)
			return false
		}
	}

	if uploadToSlack(filepath, channel) == false {
		return false
	}
	return true
}

func uploadToSlack(filename, channel string) bool {
	debugLog("uploading.. " + filename)

	api := slack.New(os.Getenv("SLACK_BOT_TOKEN"))
	params := slack.FileUploadParameters{
		Title:    "upload " + filename,
		File:     filename,
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
	for i := 0; i < len(users); i++ {
		if users[i] == User {
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

func executer(userInt, hostInt int, Command, channel string) string {
	sshCommand := "cd " + udata[userInt].PWD + ";" + Command
	tmpFile := "tmp." + users[userInt]
	if needSCP == true {
		writeFile(tmpFile+".bat", Command, userInt, true)

		scpFlag := false
		for i := 0; i < RETRY; i++ {
			if scpDo(hostInt, tmpFile+".bat") == true {
				scpFlag = true
				break
			}
		}
		if scpFlag == false {
			return ""
		}
		sshCommand = hosts[hostInt].SHEBANG + " " + tmpFile + ".bat"
	}

	var err error

	prompt := "[@" + botName + " " + udata[userInt].PWD + "]$ " + Command + "\n"
	done := false
	strs := ""
	for i := 0; i < RETRY; i++ {
		strs, done, err = sshDo(hostInt, sshCommand)
		if done == true && len(strs) > 0 {
			if strings.Count(strs, "\n") > toFile {
				writeFile(tmpFile+".txt", prompt+strs, userInt, false)
				if uploadToSlack(tmpFile+".txt", channel) == false {
					return ""
				}
				return "<@" + udata[userInt].ID + ">"
			}
			break
		}
	}
	if done == false {
		return ""
	}

	if strings.Index(Command, "pwd") == 0 {
		return "<@" + udata[userInt].ID + ">\n```\n" + prompt + udata[userInt].PWD + "\n" + "```"
	}

	if err == nil && strings.Index(Command, "cd ") == 0 {
		stra := strings.Split(Command, "cd ")
		udata[userInt].PWD = stra[1]
	}

	if len(strs) > 1 {
		return "<@" + udata[userInt].ID + ">\n```\n" + prompt + strs + "```"
	}
	return "<@" + udata[userInt].ID + ">\n```\n" + prompt + "```"
}

func sshDo(hostInt int, Command string) (string, bool, error) {
	ssh := &easyssh.MakeConfig{
		User:     hosts[hostInt].USER,
		Server:   hosts[hostInt].HOST,
		Password: hosts[hostInt].PASSWD,
		Port:     hosts[hostInt].PORT,
		Timeout:  60 * time.Second,
	}

	if Exists(hosts[hostInt].PASSWD) == true {
		ssh = &easyssh.MakeConfig{
			User:       hosts[hostInt].USER,
			Server:     hosts[hostInt].HOST,
			KeyPath:    hosts[hostInt].PASSWD,
			Port:       hosts[hostInt].PORT,
			Timeout:    60 * time.Second,
			Passphrase: "",
		}
	}

	debugLog("ssh: " + Command)

	stdout, stderr, done, err := ssh.Run(Command, 60*time.Second)

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

func scpDo(hostInt int, tmpFile string) bool {
	config := &ssh.ClientConfig{
		User:            hosts[hostInt].USER,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(hosts[hostInt].PASSWD),
		},
	}

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

	session, err := client.NewSession()
	if err != nil {
		fmt.Print(err.Error())
		return false
	}
	err = scp.CopyPath(tmpFile, ".", session)
	if err != nil {
		fmt.Print(err.Error())
		return false
	}
	defer session.Close()
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
