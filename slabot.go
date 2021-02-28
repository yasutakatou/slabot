/*
 * (detail)
 *
 * @author    yasutakatou
 * @copyright 2021 yasutakatou
 * @license   (???)
 */
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/appleboy/easyssh-proxy"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/ini.v1"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	debug     bool
	needSCP   bool
	RETRY     int
	users     []string
	permitCMD []string
	hosts     []hostsData
	udata     []userData
	botName   string = "@slabot "
)

type userData struct {
	ID   string
	PWD  string
	HOST int
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
	_Config := flag.String("config", ".slabot", "[-config=config file)]")
	_Api := flag.Bool("api", false, "[-api=api mode (true is enable)]")
	_cert := flag.String("cert", "localhost.pem", "[-cert=ssl_certificate file path (if you don't use https, haven't to use this option)]")
	_key := flag.String("key", "localhost-key.pem", "[-key=ssl_certificate_key file path (if you don't use https, haven't to use this option)]")
	_port := flag.String("port", "8080", "[-port=port number]")
	_needSCP := flag.Bool("scp", true, "[-scp=need scp mode (true is enable)]")
	_RETRY := flag.Int("retry", 10, "[-retry=retry counts.]")

	flag.Parse()

	needSCP = bool(*_needSCP)
	debug = bool(*_Debug)
	Config := string(*_Config)
	RETRY = int(*_RETRY)

	if Exists(Config) == true {
		loadConfig(Config)
	} else {
		fmt.Printf("Fail to read config file: %v\n", Config)
		os.Exit(1)
	}

	if *_Api == true {
		http.HandleFunc("/api", apiHandler)
		go func() {
			err := http.ListenAndServeTLS(":"+string(*_port), string(*_cert), string(*_key), nil)
			if err != nil {
				log.Fatal("ListenAndServeTLS: ", err)
			}
		}()
	} else {
		http.HandleFunc("/slack/events", slackHandler)
		go func() {
			if err := http.ListenAndServe(":"+string(*_port), nil); err != nil {
				log.Fatal(err)
			}
		}()
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

			if debug == true {
				fmt.Println("slack call: ", r.RemoteAddr, r.URL.Path, event.User, command)
			}

			trueFalse, text := eventSwitcher(event.User, command)

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

func eventSwitcher(User, Command string) (bool, string) {
	trueFalse := false
	data := ""

	if debug == true {
		fmt.Println("User: " + User + " Command: " + Command)
	}

	if allowUser(User) == false {
		trueFalse = false
		data = User + " : user not allow"
	} else if strings.Index(Command, "cd ") == 0 {
		stra := strings.Split(Command, "cd ")
		udata[checkUsers(User)].PWD = stra[1]

		trueFalse = true
		data = stra[1] + " : pwd set"
	} else if strings.Index(Command, "SETHOST=") == 0 {
		stra := strings.Split(Command, "SETHOST=")
		hostInt := hostCheck(stra[1])
		if hostInt == -1 {
			if debug == true {
				fmt.Println("Error: host not found. ", User, Command)
			}

			trueFalse = false
			data = stra[1] + " : host not found"
		} else {
			udata[checkUsers(User)].HOST = hostInt

			trueFalse = true
			data = stra[1] + " : host set"
		}
	} else {
		if checkHost(User) == true {
			trueFalse, data = checkPreExecuter(User, Command, udata[checkUsers(User)].HOST)
		} else {
			trueFalse = false
			data = Command + ": host not set"
		}
	}
	return trueFalse, data
}

func writeFile(filename, stra string, userInt int) bool {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer file.Close()

	_, err = file.WriteString("cd " + udata[userInt].PWD + "\n")
	_, err = file.WriteString(stra + "\n")
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func loadConfig(filename string) {
	loadOptions := ini.LoadOptions{}
	loadOptions.UnparseableSections = []string{"ALLOWID", "PERMIT", "HOSTS"}

	cfg, err := ini.LoadSources(loadOptions, filename)
	if err != nil {
		fmt.Printf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	setSingleConfigStrs(&users, "ALLOWID", cfg.Section("ALLOWID").Body())
	setSingleConfigStrs(&permitCMD, "PERMIT", cfg.Section("PERMIT").Body())
	setSingleConfigHosts(&hosts, "HOSTS", cfg.Section("HOSTS").Body())
}

func setSingleConfigStrs(config *[]string, configType, datas string) {
	if debug == true {
		fmt.Println(" -- " + configType + " --")
	}
	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if len(v) > 0 {
			*config = append(*config, v)
		}
		if debug == true {
			fmt.Println(v)
		}
	}
}

func setSingleConfigHosts(config *[]hostsData, configType, datas string) {
	if debug == true {
		fmt.Println(" -- " + configType + " --")
	}
	for _, v := range regexp.MustCompile("\r\n|\n\r|\n|\r").Split(datas, -1) {
		if len(v) > 0 {
			if strings.Index(v, ",") != -1 {
				strs := strings.Split(v, ",")
				*config = append(*config, hostsData{RULE: strs[0], HOST: strs[1], PORT: strs[2], USER: strs[3], PASSWD: strs[4], SHEBANG: strs[5]})
			}
		}
		if debug == true {
			fmt.Println(v)
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
	udata = append(udata, userData{ID: User, HOST: -1, PWD: "~/"})
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

	if debug == true {
		fmt.Println("api call: ", r.RemoteAddr, r.URL.Path, p.User, p.Command)
	}

	data := responseData{Status: "", Message: ""}

	trueFalse, text := eventSwitcher(p.User, p.Command)

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

func checkPreExecuter(User, Command string, hostInt int) (bool, string) {
	userInt := userCheck(User)
	if userInt == -1 {
		if debug == true {
			fmt.Println("Error: user not found. ", User, Command)
		}
		return false, User + ": user not found"
	}

	if len(Command) == 0 {
		if debug == true {
			fmt.Println("Error: command sring not include. ", User, Command)
		}
		return false, "command sring not include"
	}

	strs := executer(userInt, hostInt, Command)
	if len(strs) == 0 {
		return false, "command not execute"
	} else {
		return true, strs
	}
	return true, User + ":" + Command
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

func executer(userInt, hostInt int, Command string) string {
	sshCommand := "cd " + udata[userInt].PWD + ";" + Command
	if needSCP == true {
		tmpFile := "tmp." + users[userInt] + ".sh"
		writeFile(tmpFile, Command, userInt)

		scpFlag := false
		for i := 0; i < RETRY; i++ {
			if scpDo(hostInt, tmpFile) == true {
				scpFlag = true
				break
			}
		}
		if scpFlag == false {
			return ""
		}
		sshCommand = hosts[hostInt].SHEBANG + " " + tmpFile
	}

	sshFlag := false
	strs := ""
	for i := 0; i < RETRY; i++ {
		strs = sshDo(hostInt, sshCommand)
		if len(strs) > 0 {
			sshFlag = true
			break
		}
	}
	if sshFlag == false {
		return ""
	}
	return strs
}

func sshDo(hostInt int, Command string) string {
	if debug == true {
		fmt.Println("ssh: ", Command)
	}
	ssh := &easyssh.MakeConfig{
		User:     hosts[hostInt].USER,
		Server:   hosts[hostInt].HOST,
		Password: hosts[hostInt].PASSWD,
		Port:     hosts[hostInt].PORT,
		Timeout:  60 * time.Second,
	}

	stdout, stderr, done, err := ssh.Run(Command, 60*time.Second)

	if err != nil {
		panic("Can't run remote command: " + err.Error())
		return ""
	} else {
		if debug == true {
			fmt.Println("don is :", done, "stdout is :", stdout, ";   stderr is :", stderr)
		}
		fmt.Println(len(stdout))
		fmt.Println(len(stderr))

		if done == true {
			if len(stdout) > 0 {
				return stdout
			} else if len(stderr) > 0 {
				return stderr
			} else {
				return " "
			}
		}
	}
	return ""
}

func scpDo(hostInt int, tmpFile string) bool {
	config := &ssh.ClientConfig{
		User:            hosts[hostInt].USER,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(hosts[hostInt].PASSWD),
		},
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
