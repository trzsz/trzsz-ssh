/*
MIT License

Copyright (c) 2023-2025 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"fmt"
	"os"
	"strings"
)

var english = map[string]string{
	"tools/help":     "-- Press Enter to accept the default options provided in brackets. Ctrl+C to exit.",
	"newhost/title":  "================================= Add New Host =================================",
	"newhost/config": "-- Generally, just press Enter to use the default configuration path in brackets.",
	"newhost/alias":  "-- Give the server an alias as you like.",
	"newhost/host":   "-- Enter the IP address or domain name of the server.",
	"newhost/port":   "-- Enter the server port, the default is 22.",
	"newhost/user":   "-- Enter your login username.",
	"newhost/passwd": "-- Public key authentication or no need to remember password, press Enter to skip.",
	"newhost/login":  "-- Added successfully, enter Y or Yes (case insensitive) to log in immediately.",
}

var chinese = map[string]string{
	"tools/help":     "-- 可以直接按回车键接受括号内提供的默认选项，使用 Ctrl+C 可以立即退出",
	"newhost/title":  "================================ 新增服务器配置 ================================",
	"newhost/config": "-- SSH 配置文件路径，一般直接按回车键使用括号内的默认值即可。",
	"newhost/alias":  "-- 随便给服务器起个别名，如设置为 xxx 则可以使用 tssh xxx 快速登录此服务器。",
	"newhost/host":   "-- 请输入服务器 IP。如果是使用域名登录的，也可以输入服务器域名。",
	"newhost/port":   "-- 请输入服务器端口，默认是22。",
	"newhost/user":   "-- 请输入登录用户名。",
	"newhost/passwd": "-- 使用公私钥登录，或者无需记住密码，请直接按回车跳过。",
	"newhost/login":  "-- 新服务器配置已成功写入，输入 Y 或 Yes（ 不区分大小写 ）可以立即登录。",
}

func getText(key string) string {
	switch userConfig.language {
	case "english":
		return english[key]
	case "chinese":
		return chinese[key]
	default:
		return english[key]
	}
}

func chooseLanguage() {
	switch strings.ToLower(userConfig.language) {
	case "english":
		userConfig.language = "english"
		return
	case "chinese":
		userConfig.language = "chinese"
		return
	}
	if userConfig.language != "" {
		warning("Language [%s] is not support yet, English will be used by default.", userConfig.language)
		return
	}

	language := promptList("Please choose your preferred language", "", []string{"English", "简体中文"})
	switch language {
	case "English":
		language = "English"
		userConfig.language = "english"
	case "简体中文":
		language = "Chinese"
		userConfig.language = "chinese"
	}

	path := getTsshConfigPath(true)
	if err := writeLanguage(path, language); err != nil {
		warning("write language [%s] to %s failed:", language, path, err)
		return
	}
	toolsInfo(fmt.Sprintf("Language = %s", language), "has been written to %s", path)
}

func writeLanguage(path, language string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := ensureNewline(file); err != nil {
		return err
	}
	return writeAll(file, fmt.Appendf(nil, "Language = %s\n", language))
}
