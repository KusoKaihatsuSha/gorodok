package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	path_download_meter     = "path_download_meter"
	path_download_data_zip  = "path_download_data_zip"
	path_download_data      = "path_download_data"
	path_upload_data_zip    = "path_upload_data_zip"
	path_upload_data        = "path_upload_data"
	path_logs               = "path_logs"
	mail_sender_alias       = "mail_sender_alias"
	mail_sender_email       = "mail_sender_email"
	mail_recipients_email   = "mail_recipients_email"
	mail_server             = "mail_server"
	mail_error_subject      = "mail_error_subject"
	mail_error_body         = "mail_error_body"
	arm_login               = "arm_login"
	arm_password            = "arm_password"
	arm_server              = "arm_server"
	arm_trying              = "arm_trying"
	upload_mask             = "upload_mask"
	unzip_without_subfolder = "unzip_without_subfolder"
	delete_ziped            = "delete_ziped"
	last_days               = "last_days"

	error_text = "Error:"
	begin_text = "Start:"
	end_text   = "Complete:"

	arm_trying_sleep = 30 * time.Second
	timeout          = 5 * time.Second
)

var (
	p            = fmt.Println
	sprintf      = fmt.Sprintf
	settingsFile = "settings.ini"
)

type Settings struct {
	PathDownloadMeter     string `json:"path_download_meter" default:"folder\\meters.txt"`
	PathDownloadDataZip   string `json:"path_download_data_zip" default:"folder\\Pays\\"`
	PathDownloadData      string `json:"path_download_data" default:"folder\\Pays\\"`
	PathUploadDataZip     string `json:"path_upload_data_zip" default:"folder\\Saldo\\"`
	PathUploadData        string `json:"path_upload_data" default:"folder\\Saldo\\"`
	PathLogs              string `json:"path_logs" default:"folder\\Logs\\"`
	MailSenderAlias       string `json:"mail_sender_alias" default:"INFO"`
	MailSenderEmail       string `json:"mail_sender_email" default:"info@info.info"`
	MailRecipientsEmail   string `json:"mail_recipients_email" default:"r1@info.info;r2@info.info"`
	MailServer            string `json:"mail_server" default:"10.10.10.10:25"`
	MailErrorSubject      string `json:"mail_error_subject" default:"error"`
	MailErrorBody         string `json:"mail_error_body" default:"<b style='color:red'>ERROR</b>"`
	ArmServer             string `json:"arm_server" default:"https://172.0.0.1"`
	ArmLogin              string `json:"arm_login" default:"login"`
	ArmPassword           string `json:"arm_password" default:"password"`
	ArmTrying             int    `json:"arm_trying" default:"5"`
	UploadMask            string `json:"upload_mask" default:"rsaldo_(in|ra|ra_p|s|inb|p|o|z)\\.txt$"`
	UnzipWithoutSubfolder bool   `json:"unzip_without_subfolder" default:"true"`
	DeleteZiped           bool   `json:"delete_ziped" default:"true"`
	LastDays              int    `json:"last_days" default:"10"`
}

type MyHttp struct {
	Debug       bool
	Http        *http.Client
	Login       string
	Password    string
	Cookies     []*http.Cookie
	CookiesJar  *cookiejar.Jar
	CookiesStr  string
	Host        string
	Token       string
	JSESID      string
	TGT         string
	EmailServer string
	Port        int
	Settings    Settings
	Data        string
	Day         string
	DayEnd      string
	Month       string
	Year        string
	Error       string
}

type EmailUser struct {
	Username    string
	Password    string
	EmailServer string
	Port        int
}

type UploadRegistryFileReturn struct {
	FileID  int    `json:"fileId"`
	Message string `json:"message"`
}

func randomString(l int) string {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		switch randInt(1, 7) {
		case 1:
			bytes[i] = byte(randInt(48, 57))
		case 2:
			bytes[i] = byte(randInt(65, 90))
		case 3:
			bytes[i] = byte(randInt(97, 122))
		default:
			bytes[i] = byte(randInt(97, 122))
		}
	}
	return string(bytes)
}

func randInt(min int64, max int64) int {
	return_, _ := rand.Int(rand.Reader, big.NewInt(max-min))
	var return__ int64
	if return_.Int64() < min {
		return__ = return_.Int64() + min
	} else {
		return__ = return_.Int64()
	}
	return int(return__)
}

func (o *MyHttp) ToError(test string) {
	if test != "" {
		o.log(test)
	}
	o.Error = o.Error + "\n" + test
}

func exists(path string) bool {
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return true
	}
	return false
}

func (o *MyHttp) addHeader(boundary ...string) map[string]string {
	parameters := make(map[string]string)
	parameters["Host"] = o.Host
	if len(boundary) > 0 {
		parameters["Content-Type"] = "multipart/form-data; boundary=" + boundary[0]
	} else {
		parameters["Content-Type"] = "application/x-www-form-urlencoded"
	}
	parameters["Cookie"] = o.CookiesStr
	return parameters
}

func (o *MyHttp) mail() {
	if o.Error != "" {
		errorsAll := strings.Split(o.Error, "\n")
		body := ""
		for _, v := range errorsAll {
			body += `<div style="font-family:monospace;border:dashed 1px #634f36;display:inline;background:#fffff5;white-space:nowrap;">` + v + "</div><br>"
		}
		rec_list := strings.Split(o.Settings.MailRecipientsEmail, ";")
		to_name := ""
		t_ := ""
		for i := 1; i <= len(rec_list); i++ {
			if i == len(rec_list) {
				t_ += rec_list[i-1]
			} else {
				t_ += rec_list[i-1] + "; "
			}
		}
		part1 := fmt.Sprintf("From: %s<%s>\r\nTo: %s <%s>\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed", o.Settings.MailSenderAlias, o.Settings.MailSenderEmail, to_name, t_, o.Settings.MailErrorSubject)
		part2 := fmt.Sprintf("\r\nContent-Type: text/html\r\n\r\n%s\r\n", body+`<br><br>`+o.Settings.MailErrorBody)
		c, _ := smtp.Dial(o.Settings.MailServer)
		c.Mail(o.Settings.MailSenderEmail)
		for i := 1; i <= len(rec_list); i++ {
			c.Rcpt(rec_list[i-1])
		}
		w, _ := c.Data()
		w.Write([]byte(part1 + part2))
		w.Close()
		c.Quit()
	}
}

func (o *MyHttp) query(hostURL string, Method string, body *bytes.Reader, parameters map[string]string, CookiesJar *cookiejar.Jar) ([]byte, string) {
	i := 1
	iend := o.Settings.ArmTrying
	for {
		cookiesRet := ""
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		req, err := http.NewRequest(Method, hostURL, body)
		if err != nil {
			o.log(err.Error())
			time.Sleep(arm_trying_sleep)
			o.log("bad trying №" + sprintf("%d", i) + " " + time.Now().Format("2006.01.02 15:04:05"))
			if i == iend {
				break
			} else {
				i++
				continue
			}
		}
		for k, v := range parameters {
			req.Header.Add(k, v)
		}
		client := &http.Client{
			CheckRedirect: nil,
			Jar:           CookiesJar,
			Transport:     tr,
		}
		resp, err := client.Do(req)
		if err != nil {
			o.log(err.Error())
			time.Sleep(arm_trying_sleep)
			o.log("bad trying №" + sprintf("%d", i) + " " + time.Now().Format("2006.01.02 15:04:05"))
			if i == iend {
				break
			} else {
				i++
				continue
			}
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			o.log(err.Error())
			time.Sleep(arm_trying_sleep)
			o.log("bad trying №" + sprintf("%d", i) + " " + time.Now().Format("2006.01.02 15:04:05"))
			if i == iend {
				break
			} else {
				i++
				continue
			}
		}
		defer resp.Body.Close()
		Cookies := CookiesJar.Cookies(req.URL)
		for i := 0; i < len(Cookies); i++ {
			cookiesRet += Cookies[i].Name + "=" + Cookies[i].Value + ";"
		}
		return b, cookiesRet
	}
	o.ToError("Try to connect (" + sprintf("%d", i) + " times) to " + hostURL)
	return []byte{}, ""
}

func (o *MyHttp) PreLoginTo() {
	h := o.Host + "/cas/login" + "?service=" + url.QueryEscape(o.Host+"/webprovider/j_spring_cas_security_check")
	var b []byte
	b, o.CookiesStr = o.query(h, "GET", bytes.NewReader(nil), o.addHeader(), o.CookiesJar)
	re := regexp.MustCompile("jsessionid=.+?service")
	if b != nil {
		o_JSESID := re.FindAllStringSubmatch(string(b), -1)
		if o_JSESID != nil {
			o.JSESID = o_JSESID[0][0]
		}
	}
	o.log(end_text + "[PRELOGIN]")
}

func (o *MyHttp) LoginTo() {
	if o.JSESID == "" {
		o.ToError("stage PRELOAD error")
		return
	}
	h := o.Host + "/cas/login;" + o.JSESID + "=" + url.QueryEscape(o.Host+"/webprovider/j_spring_cas_security_check")
	v := url.Values{}
	v.Add("username", o.Login)
	v.Add("password", o.Password)
	v.Add("lt", "")
	v.Add("execution", "e1s1")
	v.Add("_eventId", "submit")
	v.Add("submit", "ВОЙТИ")
	_, o.CookiesStr = o.query(h, "POST", bytes.NewReader([]byte(v.Encode())), o.addHeader(), o.CookiesJar)
	o.log(end_text + "[LOGIN]")
}

func (o *MyHttp) DownloadMeter() {
	if o.JSESID == "" {
		return
	}
	o.log("settings - " + path_download_meter + " is " + o.Settings.PathDownloadMeter)
	h := o.Host + "/webprovider/counterReading/download"
	now := time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, -1)
	if time.Now().Day() < 21 {
		now = time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
	}
	v := url.Values{}
	period := fmt.Sprintf("%.*d/%.*d/%.*d 00:00:00 - %.*d/%.*d/%.*d 23:59:59", 2, 1, 2, now.Month(), 4, now.Year(), 2, now.Day(), 2, now.Month(), 4, now.Year())
	v.Add("period", period)
	v.Add("code_type", "UTF-8")
	o.log("period - [" + period + "]")
	var body []byte
	body, o.CookiesStr = o.query(h, "POST", bytes.NewReader([]byte(v.Encode())), o.addHeader(), o.CookiesJar)
	o.Data = string(body)
	if strings.Contains(o.Data, "<") || strings.Trim(o.Data, " ") == "" {
		o.ToError(error_text + "Format meters file")
	} else {
		o.writef(o.Settings.PathDownloadMeter)
	}
	o.log(end_text + "[DOWNLOAD METER]")
}

func (o *MyHttp) DownloadRegistry(manual bool) {
	if o.JSESID == "" {
		return
	}
	o.log("settings - " + path_download_data_zip + " is " + o.Settings.PathDownloadDataZip)
	o.log("settings - " + path_download_data + " is " + o.Settings.PathDownloadData)
	o.log("settings - " + unzip_without_subfolder + " is " + sprintf("%t", o.Settings.UnzipWithoutSubfolder))
	o.log("settings - " + last_days + " is " + sprintf("%d", o.Settings.LastDays))
	h := o.Host + "/webprovider/batchProcessing/getReestersOnZip"
	v := url.Values{}
	v.Add("dbeg", time.Now().AddDate(0, 0, -o.Settings.LastDays).Format("02.01.2006"))
	v.Add("dend", time.Now().Format("02.01.2006"))
	if !manual {
		v.Add("isSend", "1")
	}
	o.log("period - [" + v.Encode() + "]")
	var body []byte
	body, o.CookiesStr = o.query(h, "POST", bytes.NewReader([]byte(v.Encode())), o.addHeader(), o.CookiesJar)
	o.Data = string(body)
	rand := time.Now().Format("2006_01_02_15_04_05") + "__" + randomString(12)
	o.writef(o.Settings.PathDownloadDataZip + rand + ".zip")
	files := o.Unzip(o.Settings.PathDownloadDataZip+rand+".zip", o.Settings.PathDownloadData)
	for _, v := range files {
		o.log("unzip [" + v + "]")
	}
	o.log(end_text + "[DOWNLOAD REGISTRY]")
}

func (o *MyHttp) UploadRegistryFileConfirm() {
	if o.JSESID == "" {
		return
	}
	o.log("settings - " + path_upload_data_zip + " is " + o.Settings.PathUploadDataZip)
	o.log("settings - " + path_upload_data + " is " + o.Settings.PathUploadData)
	o.log("settings - " + upload_mask + " is " + o.Settings.UploadMask)
	o.log("settings - " + delete_ziped + " is " + sprintf("%t", o.Settings.DeleteZiped))
	files := []string{}
	err := getFilesInFolder(&files, o.Settings.PathUploadData, []string{}, o.Settings.UploadMask)
	if err != nil {
		o.ToError(err.Error())
	}
	newFiles := []string{}
	for _, file := range files {
		newName := file + "." + uuid() + ".txt"
		newFiles = append(newFiles, newName)
		os.Rename(file, newName)
		idFile := o.UploadRegistryFile(newName)
		o.log("file: " + newName)
		h := o.Host + "/webprovider/exchangeReeLogic/addFile"
		var body []byte
		v := url.Values{}
		v.Add("filelist", idFile)
		body, o.CookiesStr = o.query(h, "POST", bytes.NewReader([]byte(v.Encode())), o.addHeader(), o.CookiesJar)
		o.Data = string(body)
		o.log(end_text + "COMPLETE UPLOAD REGISTRY" + "[" + idFile + ": " + string(body) + "]")
	}
	o.Zip(newFiles, o.Settings.PathUploadDataZip+time.Now().Format("2006_01_02_15_04_05")+"__"+uuid()+".zip", o.Settings.DeleteZiped)
}

func uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (o *MyHttp) UploadRegistryFile(path string) string {
	h := o.Host + "/webprovider/exchangeReeLogic/setToBd"
	var body []byte
	file_, w := o.createMultipartFormData("file", path)
	data := bytes.NewReader(file_.Bytes())
	body, o.CookiesStr = o.query(h, "POST", data, o.addHeader(w.Boundary()), o.CookiesJar)
	o.Data = string(body)
	return_ := new(UploadRegistryFileReturn)
	json.Unmarshal(body, &return_)
	o.log(end_text + "UPLOAD FILE " + "[" + sprintf("%d", return_.FileID) + "]")
	return sprintf("%d", return_.FileID)
}

func (o *MyHttp) createMultipartFormData(fieldName, fileName string) (bytes.Buffer, *multipart.Writer) {
	var b bytes.Buffer
	var err error
	w := multipart.NewWriter(&b)
	var fw io.Writer
	file, err := os.Open(fileName)
	if err != nil {
		o.ToError(err.Error())
	}
	if fw, err = w.CreateFormFile(fieldName, file.Name()); err != nil {
		o.ToError(err.Error())
	}
	if _, err = io.Copy(fw, file); err != nil {
		o.ToError(err.Error())
	}
	w.Close()
	return b, w
}

func (o *MyHttp) writef(path string) {
	if o.Error == "" {
		d1 := []byte(o.Data)
		ioutil.WriteFile(path, d1, 0755)
	}
}

func fileDate(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		p(err)
	}
	return fi.ModTime().Day() >= time.Now().Day()-1
}

func (o *MyHttp) log(text string) {
	if text != "" {
		p(time.Now().Format("2006-01-02[15:04:05]")+" : ", text)
		f, err := os.OpenFile(o.Settings.PathLogs+"logs__"+time.Now().Format("2006-01")+".txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			o.ToError(err.Error())
		}
		defer f.Close()
		log.SetOutput(f)
		log.Println(time.Now().Format("2006-01-02[15:04:05]")+" : ", text)
	}
}

func (o *MyHttp) Zip(src []string, dest string, del bool) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	file, err := os.OpenFile(dest, flags, 0644)
	if err != nil {
		o.ToError(err.Error())
	}
	defer file.Close()
	zipw := zip.NewWriter(file)
	defer zipw.Close()
	for _, filename := range src {
		if err := appendFiles(filename, zipw); err != nil {
			o.ToError(err.Error())
		}
		o.log("zip [" + filename + "]")
	}
	if del {
		for _, filename := range src {
			i := 1
			for {
				if err := os.Remove(filename); err != nil {
					time.Sleep(3 * time.Second)
					i++
				} else {
					break
				}
				if i == 41 {
					o.ToError("[Failed removing file" + filename + "]")
					break
				}
			}

		}
	}
}

func appendFiles(filename string, zw *zip.Writer) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Failed to open %s: %s", filename, err)
	}
	defer file.Close()
	wr, err := zw.Create(filename)
	if err != nil {
		return fmt.Errorf("Failed to create entry for %s in zip file: %s", filename, err)
	}
	if _, err := io.Copy(wr, file); err != nil {
		return fmt.Errorf("Failed to write %s to zip: %s", filename, err)
	}
	file.Close()
	return nil
}

func getFilesInFolder(backFiles *[]string, basePath string, ignoreFilesList []string, mask string) error {
	r, err := regexp.Compile(mask)
	if err != nil {
		p(err)
	}
	checkIgrore := func(n string, il []string) bool {
		for _, ifile := range il {
			if strings.HasSuffix(n, ifile) && ifile != "" {
				return false
			}
		}
		return true
	}
	files, err := ioutil.ReadDir(basePath)
	if err != nil {
		return err
	}
	for _, file := range files {
		if !file.IsDir() && r.MatchString(file.Name()) {
			if checkIgrore(file.Name(), ignoreFilesList) {
				*backFiles = append(*backFiles, basePath+file.Name())
			}
		} else if file.IsDir() {
			getFilesInFolder(backFiles, basePath+file.Name()+string(os.PathSeparator), ignoreFilesList, mask)
		}
	}
	return nil
}

func (o *MyHttp) Unzip(src string, dest string) []string {
	var filenames []string
	r, err := zip.OpenReader(src)
	if err != nil {
		o.ToError(err.Error())
		return filenames
	}
	defer r.Close()
	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if o.Settings.UnzipWithoutSubfolder {
			tmp := strings.Replace(f.Name, `\`, string(os.PathSeparator), -1)
			tmp = strings.Replace(tmp, `/`, string(os.PathSeparator), -1)
			f_Name := strings.Split(tmp, string(os.PathSeparator))
			if len(f_Name) > 0 {
				fpath = filepath.Join(dest, f_Name[len(f_Name)-1])
			}
		}
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			o.ToError(fmt.Errorf("error file path %s", fpath).Error())
			return filenames
		}
		filenames = append(filenames, fpath)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			o.ToError(err.Error())
			return filenames
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			o.ToError(err.Error())
			return filenames
		}
		rc, err := f.Open()
		if err != nil {
			o.ToError(err.Error())
			return filenames
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			o.ToError(err.Error())
			return filenames
		}
	}
	return filenames
}

// SaveJson()
// save data to config file
func (o *MyHttp) SaveJson(default_ bool) {
	if default_ {
		type_ := reflect.TypeOf(&o.Settings)
		value_ := reflect.ValueOf(&o.Settings)
		for i := 0; i < type_.Elem().NumField(); i++ {
			if value_.Elem().Field(i).IsZero() {
				def := type_.Elem().Field(i).Tag.Get("default")
				if def != "" {
					switch type_.Elem().Field(i).Type.String() {
					case "int":
						result, _ := strconv.Atoi(def)
						value_.Elem().Field(i).SetInt(int64(result))
					case "string":
						value_.Elem().Field(i).SetString(def)
					case "bool":
						switch def {
						case "true":
							value_.Elem().Field(i).SetBool(true)
						case "false":
							value_.Elem().Field(i).SetBool(false)
						}
					}
				}
			}
		}
	}
	all, err := json.MarshalIndent(o.Settings, "", "  ")
	if err != nil {
		o.ToError(err.Error())
	}
	ioutil.WriteFile(settingsFile, all, 0775)
}

// LoadJson()
// get config file data
func (o *MyHttp) LoadJson() {
	b, err := ioutil.ReadFile(settingsFile)
	if err != nil {
		o.ToError(err.Error())
	}
	json.Unmarshal(b, &o.Settings)
}

func main() {
	meters, upload, download, manual := false, false, false, false

	dirDef, _ := os.Getwd()
	dirSettingsFile := dirDef + string(os.PathSeparator) + settingsFile

	flag.BoolVar(&meters, "meter", false, "download meters")
	flag.BoolVar(&upload, "u", false, "upload data")
	flag.BoolVar(&download, "d", false, "download data")
	flag.BoolVar(&manual, "manual", false, "download last 10 day manual")
	flag.StringVar(&settingsFile, "settings", dirSettingsFile, "file with settings")
	flag.Parse()

	flag.PrintDefaults()

	var sg MyHttp
	sg.Settings = Settings{}
	sg.LoadJson()
	if !exists(dirSettingsFile) {
		p("Not found settings file. Create Empty file")
		sg.ToError(fmt.Errorf("error file settings %s", dirSettingsFile).Error())
		sg.SaveJson(true)
	}
	sg.Login = sg.Settings.ArmLogin
	sg.Password = sg.Settings.ArmPassword
	sg.Host = sg.Settings.ArmServer
	sg.log("HOST [" + sg.Host + "]")
	sg.CookiesJar, _ = cookiejar.New(nil)
	sg.PreLoginTo()
	sg.LoginTo()
	if meters {
		sg.DownloadMeter()
	}
	if download {
		sg.DownloadRegistry(manual)
	}
	if upload {
		sg.UploadRegistryFileConfirm()
	}
	sg.mail()
}
