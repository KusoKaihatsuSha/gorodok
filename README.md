[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![godoc](https://godoc.org/github.com/KusoKaihatsuSha/gorodok?status.svg)](https://godoc.org/github.com/KusoKaihatsuSha/gorodok) [![Go Report Card](https://goreportcard.com/badge/github.com/KusoKaihatsuSha/gorodok)](https://goreportcard.com/report/github.com/KusoKaihatsuSha/gorodok)

#  Upload/Download gorodok data (unofficial app for Sistema Gorod)

> Unofficial app for billing synchronized and getting meter reading. (not public resource 'gorodok' by https://sistemagorod.ru)

`! Caution. it's version for one old NON-API resource 'gorodok'`

`! This app may be working, if your organization have legal access to servers 'gorodok' `

`! Note: official apps not worked/buildable on Linux and not get meters data`

> Functionality:

1) Downloading billing data
2) Uploading billing data
3) Downloading meters data
4) Auto zipping/unzipping data

### Accessible flags:

> Download new data

`-d`

> Download data (last 10 days)

`-d -manual`

> Download meters data

`-meter`

> Upload data

`-u`

### Configuration file description:

```json
{
  "path_download_meter": "folder\\meters.txt", // where will been saved meters data
  "path_download_data_zip": "folder\\Pays\\",  // where will been saved file ZIP
  "path_download_data": "folder\\Pays\\",      // where will been saved unziped files
  "path_upload_data_zip": "folder\\Saldo\\",   // where lay down zipped files for uploading
  "path_upload_data": "folder\\Saldo\\",       // where lay down unzipped files for uploading
  "path_logs": "folder\\Logs\\",               // where will be lay down logs
  "mail_sender_alias": "INFO",                 // sender name
  "mail_sender_email": "info@x.X",             // sender email
  "mail_recipients_email": "r1@x.X;r2@x.X",    // recipients by semicolon
  "mail_server": "10.10.10.10:25",             // mail server address (without auth)
  "mail_error_subject": "error",               // error header
  "mail_error_body": "ERROR",                  // error body
  "arm_server": "https://172.0.0.1",           // gorodok address
  "arm_login": "login",                        // gorodok login
  "arm_password": "password",                  // gorodok password
  "arm_trying": 5,                             // num trying
  "upload_mask": "rsaldo_(in|ra|ra_p|s|inb|p|o|z)\\.txt$",    // mask files
  "unzip_without_subfolder": true,             // not save folder struct by unzipped
  "delete_ziped": true,                        // clear ZIP files
  "last_days": 10                              // num days in 'manual' flag
}
```

