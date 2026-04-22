/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

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
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/trzsz/trzsz-ssh/internal/table"
)

type promptTheme struct {
	Help            string
	Label           string
	Active          string
	Inactive        string
	Details         string
	Shortcuts       string
	HideLabel       bool
	ItemsRenderer   func(items []any, idx int) string
	DetailsRenderer func(item any) string
}

func getDefaultHelpTipsTemplate() string {
	return fmt.Sprintf(`{{ "Use ← ↓ ↑ → h j k l to navigate, 0-9 jumps within page, / toggles search, ? toggles help" | %s }}`, getThemeColor("help_tips"))
}

func getDefaultShortcutsTemplate() string {
	return fmt.Sprintf(`{{ . | %s }}`, getThemeColor("shortcuts"))
}

func getDefaultDetailsTemplate() string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf(`{{ "--------- SSH Details ----------\n" | %s }}`, getThemeColor("details_title")))
	addItem := func(name string) {
		builder.WriteString(fmt.Sprintf(`{{ if hasField . "%s" }}`+
			`{{- if .%s }}{{ "%s:" | %s }}{{ "\t" }}{{ .%s | %s }}{{ "\n" }}{{ end }}`+
			`{{ else }}{{ $value := getExConfig .Alias "%s" }}`+
			`{{- if $value }}{{ "%s:" | %s }}{{ "\t" }}{{ $value | %s }}{{ "\n" }}{{ end }}`+
			`{{ end }}`,
			name, name, name, getThemeColor("details_name"), name, getThemeColor("details_value"),
			name, name, getThemeColor("details_name"), getThemeColor("details_value")))
	}
	for _, item := range getPromptDetailItems() {
		switch strings.ToLower(item) {
		case "alias":
			addItem("Alias")
		case "host":
			addItem("Host")
		case "port":
			builder.WriteString(fmt.Sprintf(
				`{{- if ne .Port "22" }}{{ "Port:" | %s }}{{ "\t" }}{{ .Port | %s }}{{ "\n" }}{{ end }}`,
				getThemeColor("details_name"), getThemeColor("details_value")))
		case "user":
			addItem("User")
		case "grouplabels":
			addItem("GroupLabels")
		case "identityfile":
			addItem("IdentityFile")
		case "proxycommand":
			addItem("ProxyCommand")
		case "proxyjump":
			addItem("ProxyJump")
		case "remotecommand":
			addItem("RemoteCommand")
		default:
			addItem(item)
		}
	}
	return builder.String()
}

func getTinyTheme() *promptTheme {
	line := newLineTheme(true)
	return &promptTheme{
		Label: fmt.Sprintf(`{{ "? " | %s }}{{ . | %s }}{{ ":" | %s }}`,
			getThemeColor("label_icon"), getThemeColor("label_text"), getThemeColor("label_text")),
		Active: fmt.Sprintf(`{{ "%s" | %s }} {{ if .Selected }}{{ "✔ " | %s }}{{ else }}{{ "  " }}{{ end }}`+
			`{{ .Alias | %s }} ({{ .Host | %s }}){{ "\t" }}{{ .GroupLabels | %s }}`,
			promptCursorIcon, getThemeColor("cursor_icon"), getThemeColor("active_selected"),
			getThemeColor("active_alias"), getThemeColor("active_host"), getThemeColor("active_group")),
		Inactive: fmt.Sprintf(`   {{ if .Selected }}{{ "✔ " | %s }}{{ else }}{{ "  " }}{{ end }}`+
			`{{ .Alias | %s }} ({{ .Host | %s }}){{ "\t" }}{{ .GroupLabels | %s }}`,
			getThemeColor("inactive_selected"),
			getThemeColor("inactive_alias"), getThemeColor("inactive_host"), getThemeColor("inactive_group")),
		Details:       getDefaultDetailsTemplate(),
		Help:          getDefaultHelpTipsTemplate(),
		ItemsRenderer: line.renderItems,
		Shortcuts:     getDefaultShortcutsTemplate(),
	}
}

func getSimpleTheme() *promptTheme {
	line := newLineTheme(false)
	return &promptTheme{
		Label: fmt.Sprintf(`{{ "? " | %s }}{{ . | %s }}{{ ":\n" | %s }}`,
			getThemeColor("label_icon"), getThemeColor("label_text"), getThemeColor("label_text")),
		Active: fmt.Sprintf(`{{ "%s" | %s }} {{ if .Selected }}{{ "✔ " | %s }}{{ else }}{{ "  " }}{{ end }}`+
			`{{ .Alias | %s }}{{ "\t" }}{{ .Host | %s }}{{ "\t" }}{{ .GroupLabels | %s }}`+
			`{{ "\n\t\t" }}`, promptCursorIcon, getThemeColor("cursor_icon"), getThemeColor("active_selected"),
			getThemeColor("active_alias"), getThemeColor("active_host"), getThemeColor("active_group")),
		Inactive: fmt.Sprintf(`   {{ if .Selected }}{{ "✔ " | %s }}{{ else }}{{ "  " }}{{ end }}`+
			`{{ .Alias | %s }}{{ "\t" }}{{ .Host | %s }}{{ "\t" }}{{ .GroupLabels | %s }}`+
			`{{ "\n\t\t" }}`, getThemeColor("inactive_selected"),
			getThemeColor("inactive_alias"), getThemeColor("inactive_host"), getThemeColor("inactive_group")),
		Details:       getDefaultDetailsTemplate(),
		Help:          getDefaultHelpTipsTemplate(),
		ItemsRenderer: line.renderItems,
		Shortcuts:     getDefaultShortcutsTemplate(),
	}
}

type lineTheme struct {
	tiny                bool
	activeCursorStyle   lipgloss.Style
	activeNumberStyle   lipgloss.Style
	inactiveNumberStyle lipgloss.Style
	activeSelectedStyle lipgloss.Style
	inactiveSelectStyle lipgloss.Style
	activeAliasStyle    lipgloss.Style
	inactiveAliasStyle  lipgloss.Style
	activeHostStyle     lipgloss.Style
	inactiveHostStyle   lipgloss.Style
	activeGroupStyle    lipgloss.Style
	inactiveGroupStyle  lipgloss.Style
}

func newLineTheme(tiny bool) *lineTheme {
	return &lineTheme{
		tiny:                tiny,
		activeCursorStyle:   getPromptLineStyle(getThemeColor("cursor_icon")),
		activeNumberStyle:   getPromptLineStyle("blue|bold"),
		inactiveNumberStyle: getPromptLineStyle("blue"),
		activeSelectedStyle: getPromptLineStyle(getThemeColor("active_selected")),
		inactiveSelectStyle: getPromptLineStyle(getThemeColor("inactive_selected")),
		activeAliasStyle:    getPromptLineStyle(getThemeColor("active_alias")),
		inactiveAliasStyle:  getPromptLineStyle(getThemeColor("inactive_alias")),
		activeHostStyle:     getPromptLineStyle(getThemeColor("active_host")),
		inactiveHostStyle:   getPromptLineStyle(getThemeColor("inactive_host")),
		activeGroupStyle:    getPromptLineStyle(getThemeColor("active_group")),
		inactiveGroupStyle:  getPromptLineStyle(getThemeColor("inactive_group")),
	}
}

func getPromptLineStyle(spec string) lipgloss.Style {
	style := lipgloss.NewStyle()
	for _, token := range strings.Split(spec, "|") {
		switch strings.TrimSpace(token) {
		case "", "default":
			continue
		case "bold":
			style = style.Bold(true)
		case "faint":
			style = style.Faint(true)
		case "underline":
			style = style.Underline(true)
		case "black":
			style = style.Foreground(lipgloss.Color("0"))
		case "red":
			style = style.Foreground(lipgloss.Color("1"))
		case "green":
			style = style.Foreground(lipgloss.Color("2"))
		case "yellow":
			style = style.Foreground(lipgloss.Color("3"))
		case "blue":
			style = style.Foreground(lipgloss.Color("4"))
		case "magenta":
			style = style.Foreground(lipgloss.Color("5"))
		case "cyan":
			style = style.Foreground(lipgloss.Color("6"))
		case "white":
			style = style.Foreground(lipgloss.Color("7"))
		default:
			style = style.Foreground(lipgloss.Color(token))
		}
	}
	return style
}

func (t *lineTheme) renderItems(items []any, idx int) string {
	view := getPromptPageView(items, idx, promptStrictPagingEnabled)
	var builder strings.Builder
	for i, host := range view.hosts {
		active := i == view.activeIdx
		if active {
			builder.WriteString(t.activeCursorStyle.Render(promptCursorIcon))
			builder.WriteString(" ")
		} else {
			builder.WriteString("   ")
		}
		number := fmt.Sprintf("%d", i)
		if active {
			builder.WriteString(t.activeNumberStyle.Render(number))
		} else {
			builder.WriteString(t.inactiveNumberStyle.Render(number))
		}
		builder.WriteString(" ")

		selectIcon := "  "
		if host.Selected {
			selectIcon = "✔ "
		}
		if active {
			builder.WriteString(t.activeSelectedStyle.Render(selectIcon))
		} else {
			builder.WriteString(t.inactiveSelectStyle.Render(selectIcon))
		}

		if active {
			builder.WriteString(t.activeAliasStyle.Render(host.Alias))
		} else {
			builder.WriteString(t.inactiveAliasStyle.Render(host.Alias))
		}

		if t.tiny {
			builder.WriteString(" (")
			if active {
				builder.WriteString(t.activeHostStyle.Render(host.Host))
			} else {
				builder.WriteString(t.inactiveHostStyle.Render(host.Host))
			}
			builder.WriteString(")")
		} else {
			builder.WriteString("\t")
			if active {
				builder.WriteString(t.activeHostStyle.Render(host.Host))
			} else {
				builder.WriteString(t.inactiveHostStyle.Render(host.Host))
			}
		}

		if host.GroupLabels != "" {
			builder.WriteString("\t")
			if active {
				builder.WriteString(t.activeGroupStyle.Render(host.GroupLabels))
			} else {
				builder.WriteString(t.inactiveGroupStyle.Render(host.GroupLabels))
			}
		}

		if i < len(view.hosts)-1 {
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

const (
	cyberpunkLeftWidth       = 46
	cyberpunkProfileWidth    = 34
	cyberpunkProfileMinWidth = 98
)

type cyberpunkTheme struct {
	labelIconStyle       lipgloss.Style
	labelTextStyle       lipgloss.Style
	activeCursorStyle    lipgloss.Style
	activeNumberStyle    lipgloss.Style
	inactiveNumberStyle  lipgloss.Style
	activeSelectedStyle  lipgloss.Style
	inactiveSelectStyle  lipgloss.Style
	activeAliasStyle     lipgloss.Style
	inactiveAliasStyle   lipgloss.Style
	activeHostStyle      lipgloss.Style
	inactiveHostStyle    lipgloss.Style
	activeBusStyle       lipgloss.Style
	inactiveBusStyle     lipgloss.Style
	profileBorderStyle   lipgloss.Style
	profileTitleStyle    lipgloss.Style
	profileNameStyle     lipgloss.Style
	profileValueStyle    lipgloss.Style
	profileFallbackStyle lipgloss.Style
}

func newCyberpunkTheme() *cyberpunkTheme {
	return &cyberpunkTheme{
		labelIconStyle:       getPromptLineStyle(getThemeColor("label_icon")),
		labelTextStyle:       getPromptLineStyle(getThemeColor("label_text")),
		activeCursorStyle:    getPromptLineStyle(getThemeColor("cursor_icon")),
		activeNumberStyle:    getPromptLineStyle(getThemeColor("active_number")),
		inactiveNumberStyle:  getPromptLineStyle(getThemeColor("inactive_number")),
		activeSelectedStyle:  getPromptLineStyle(getThemeColor("active_selected")),
		inactiveSelectStyle:  getPromptLineStyle(getThemeColor("inactive_selected")),
		activeAliasStyle:     getPromptLineStyle(getThemeColor("active_alias")),
		inactiveAliasStyle:   getPromptLineStyle(getThemeColor("inactive_alias")),
		activeHostStyle:      getPromptLineStyle(getThemeColor("active_host")),
		inactiveHostStyle:    getPromptLineStyle(getThemeColor("inactive_host")),
		activeBusStyle:       getPromptLineStyle(getThemeColor("bus_active")),
		inactiveBusStyle:     getPromptLineStyle(getThemeColor("bus_inactive")),
		profileBorderStyle:   getPromptLineStyle(getThemeColor("profile_border")),
		profileTitleStyle:    getPromptLineStyle(getThemeColor("profile_title")),
		profileNameStyle:     getPromptLineStyle(getThemeColor("profile_name")),
		profileValueStyle:    getPromptLineStyle(getThemeColor("profile_value")),
		profileFallbackStyle: getPromptLineStyle(getThemeColor("profile_empty")),
	}
}

func fitPlainText(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(s) > width {
		return ansi.Truncate(s, width, "…")
	}
	return s + strings.Repeat(" ", width-ansi.StringWidth(s))
}

func fitStyledText(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(s) > width {
		return ansi.Truncate(s, width, "…")
	}
	return s + strings.Repeat(" ", width-ansi.StringWidth(s))
}

func getPromptTerminalWidth() int {
	if width := int(currentTerminalWidth.Load()); width > 0 {
		return width
	}
	if isTerminal {
		if width, _, err := getTerminalSize(); err == nil && width > 0 {
			return width
		}
	}
	return 120
}

func (t *cyberpunkTheme) showProfilePanel() bool {
	return getPromptTerminalWidth() >= cyberpunkProfileMinWidth
}

func (t *cyberpunkTheme) renderLeftLine(host *sshHost, idx int, active bool) string {
	cursor := "  "
	if active {
		cursor = t.activeCursorStyle.Render(promptCursorIcon) + " "
	}

	number := fitPlainText(fmt.Sprintf("%d", idx), 2)
	if active {
		number = t.activeNumberStyle.Render(number)
	} else {
		number = t.inactiveNumberStyle.Render(number)
	}

	selected := "  "
	if host.Selected {
		selected = fitPlainText(promptSelectedIcon, 2)
	}
	if active {
		selected = t.activeSelectedStyle.Render(selected)
	} else {
		selected = t.inactiveSelectStyle.Render(selected)
	}

	alias := fitPlainText(host.Alias, 15)
	if active {
		alias = t.activeAliasStyle.Render(alias)
	} else {
		alias = t.inactiveAliasStyle.Render(alias)
	}

	hostName := fitPlainText(host.Host, 22)
	if active {
		hostName = t.activeHostStyle.Render(hostName)
	} else {
		hostName = t.inactiveHostStyle.Render(hostName)
	}

	return fitStyledText(fmt.Sprintf("%s%s %s %s %s", cursor, number, selected, alias, hostName), cyberpunkLeftWidth)
}

func (t *cyberpunkTheme) getProfileValues(host *sshHost) [][2]string {
	port := host.Port
	if port == "" {
		port = "22"
	}
	group := host.GroupLabels
	if group == "" {
		group = "-"
	}

	auth := "default"
	if host.IdentityFile != "" {
		auth = "key"
	}
	if getExConfig(host.Alias, "encPassword") != "" || getExConfig(host.Alias, "Password") != "" {
		if auth == "key" {
			auth = "key / password cache"
		} else {
			auth = "password cache"
		}
	}

	route := "direct"
	if host.ProxyJump != "" {
		route = "jump: " + host.ProxyJump
	} else if host.ProxyCommand != "" {
		route = "command"
	}

	return [][2]string{
		{"ALIAS", host.Alias},
		{"HOST", host.Host},
		{"USER", host.User},
		{"PORT", port},
		{"GROUP", group},
		{"AUTH", auth},
		{"ROUTE", route},
	}
}

func (t *cyberpunkTheme) renderProfileLine(name, value string) string {
	const nameWidth = 7
	innerWidth := cyberpunkProfileWidth - 2
	valueWidth := innerWidth - nameWidth - 2
	name = t.profileNameStyle.Render(fitPlainText(name, nameWidth))
	if value == "" {
		value = "-"
	}
	valueStyle := t.profileValueStyle
	if value == "-" {
		valueStyle = t.profileFallbackStyle
	}
	value = valueStyle.Render(fitPlainText(value, valueWidth))
	return t.profileBorderStyle.Render("│") + " " + name + " " + value + t.profileBorderStyle.Render("│")
}

func (t *cyberpunkTheme) renderProfilePanel(host *sshHost) []string {
	innerWidth := cyberpunkProfileWidth - 2
	title := "[ NODE PROFILE ]"
	topFill := innerWidth - 1 - ansi.StringWidth(title)
	if topFill < 0 {
		topFill = 0
	}
	lines := []string{
		t.profileBorderStyle.Render("╭─") + t.profileTitleStyle.Render(title) +
			t.profileBorderStyle.Render(strings.Repeat("─", topFill)+"╮"),
	}
	for _, item := range t.getProfileValues(host) {
		lines = append(lines, t.renderProfileLine(item[0], item[1]))
	}
	lines = append(lines, t.profileBorderStyle.Render("╰"+strings.Repeat("─", innerWidth)+"╯"))
	return lines
}

func (t *cyberpunkTheme) renderItems(items []any, idx int) string {
	view := getPromptPageView(items, idx, promptStrictPagingEnabled)
	if len(view.hosts) == 0 {
		return ""
	}

	leftLines := []string{
		fitStyledText(t.labelIconStyle.Render("? ")+t.labelTextStyle.Render("SSH Alias:"), cyberpunkLeftWidth),
	}
	for i, host := range view.hosts {
		leftLines = append(leftLines, t.renderLeftLine(host, i, i == view.activeIdx))
	}

	if !t.showProfilePanel() || view.activeIdx < 0 || view.activeIdx >= len(view.hosts) {
		return strings.Join(leftLines, "\n")
	}

	profileLines := t.renderProfilePanel(view.hosts[view.activeIdx])
	totalLines := len(leftLines)
	if len(profileLines) > totalLines {
		totalLines = len(profileLines)
	}

	var builder strings.Builder
	for i := 0; i < totalLines; i++ {
		left := strings.Repeat(" ", cyberpunkLeftWidth)
		if i < len(leftLines) {
			left = fitStyledText(leftLines[i], cyberpunkLeftWidth)
		}

		bus := t.inactiveBusStyle.Render("┆")
		if i == view.activeIdx+1 {
			bus = t.activeBusStyle.Render("┃")
		}

		profile := ""
		if i < len(profileLines) {
			profile = profileLines[i]
		}

		builder.WriteString(left)
		builder.WriteString(" ")
		builder.WriteString(bus)
		builder.WriteString("  ")
		builder.WriteString(profile)
		if i < totalLines-1 {
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

func (t *cyberpunkTheme) renderDetails(item any) string {
	if t.showProfilePanel() {
		return ""
	}
	host, ok := item.(*sshHost)
	if !ok {
		return ""
	}
	return strings.Join(t.renderProfilePanel(host), "\n")
}

func getCyberpunkTheme() *promptTheme {
	cyberpunk := newCyberpunkTheme()
	return &promptTheme{
		HideLabel:       true,
		Help:            getDefaultHelpTipsTemplate(),
		Shortcuts:       getDefaultShortcutsTemplate(),
		ItemsRenderer:   cyberpunk.renderItems,
		DetailsRenderer: cyberpunk.renderDetails,
	}
}

type tableTheme struct {
	tableHeaderStyle    lipgloss.Style
	defaultAliasStyle   lipgloss.Style
	defaultHostStyle    lipgloss.Style
	defaultGroupStyle   lipgloss.Style
	selectedIconStyle   lipgloss.Style
	selectedAliasStyle  lipgloss.Style
	selectedHostStyle   lipgloss.Style
	selectedGrouplStyle lipgloss.Style
	defaultBorderStyle  lipgloss.Style
	selectedBorderStyle lipgloss.Style
	detailsNameStyle    lipgloss.Style
	detailsValueStyle   lipgloss.Style
	detailsBorderStyle  lipgloss.Style
	tableWidth          int
}

func (t *tableTheme) cellStyle(host *sshHost, row, col int) lipgloss.Style {
	if row == 0 {
		return t.tableHeaderStyle
	}
	if col == 1 {
		return t.selectedIconStyle
	}
	if host.Selected {
		switch col {
		case 0, 2:
			return t.selectedAliasStyle
		case 3:
			return t.selectedHostStyle
		case 4:
			return t.selectedGrouplStyle
		}
	} else {
		switch col {
		case 0, 2:
			return t.defaultAliasStyle
		case 3:
			return t.defaultHostStyle
		case 4:
			return t.defaultGroupStyle
		}
	}
	return lipgloss.NewStyle()
}

func (t *tableTheme) borderStyle(idx, row, col int, borderType table.BorderType) lipgloss.Style {
	switch row {
	case idx:
		switch borderType {
		case table.BorderBottom:
			return t.selectedBorderStyle
		}
	case idx + 1:
		switch borderType {
		case table.BorderLeft:
			if col == 0 {
				return t.selectedBorderStyle
			}
		case table.BorderRight, table.BorderBottom:
			return t.selectedBorderStyle
		}
	}
	return t.defaultBorderStyle
}

func (t *tableTheme) renderItems(items []any, idx int) string {
	view := getPromptPageView(items, idx, promptStrictPagingEnabled)
	var data [][]string
	for _, host := range view.hosts {
		icon := " "
		if host.Selected {
			icon = "✔"
		}
		data = append(data, []string{fmt.Sprintf("%d", len(data)), icon, host.Alias, host.Host, host.GroupLabels})
	}
	tbl := table.New().BorderRow(true).
		Headers("No.", "", "Alias", "Host Name", "Group Labels").Rows(data...).
		StyleFunc(func(row, col int) lipgloss.Style {
			var host *sshHost
			if row > 0 {
				host = view.hosts[row-1]
			}
			return t.cellStyle(host, row, col)
		}).
		BorderStyleFunc(func(row, col int, borderType table.BorderType) lipgloss.Style {
			return t.borderStyle(view.activeIdx, row, col, borderType)
		})
	result := tbl.String()
	t.tableWidth = tbl.GetTotalWidth()
	return result
}

func (t *tableTheme) renderDetails(item any) string {
	host := item.(*sshHost)
	var data [][]string
	addItem := func(name, value string) {
		if value != "" {
			data = append(data, []string{name, value})
		}
	}
	for _, item := range getPromptDetailItems() {
		switch strings.ToLower(item) {
		case "alias":
			addItem("Alias", host.Alias)
		case "host":
			addItem("Host", host.Host)
		case "port":
			if host.Port != "22" {
				data = append(data, []string{"Port", host.Port})
			}
		case "user":
			addItem("User", host.User)
		case "grouplabels":
			addItem("GroupLabels", host.GroupLabels)
		case "identityfile":
			addItem("IdentityFile", host.IdentityFile)
		case "proxycommand":
			addItem("ProxyCommand", host.ProxyCommand)
		case "proxyjump":
			addItem("ProxyJump", host.ProxyJump)
		case "remotecommand":
			addItem("RemoteCommand", host.RemoteCommand)
		default:
			addItem(item, getExConfig(host.Alias, item))
		}
	}
	tbl := table.New().BorderRow(true).Rows(data...).
		BorderStyle(t.detailsBorderStyle).
		StyleFunc(func(row, col int) lipgloss.Style {
			if col == 0 {
				return t.detailsNameStyle
			}
			return t.detailsValueStyle
		}).FixedColumns(0)
	if t.tableWidth > 0 {
		tbl.Width(t.tableWidth)
	}
	return tbl.String()
}

func getTableTheme() *promptTheme {
	baseStyle := lipgloss.NewStyle()
	cellStyle := baseStyle.Padding(0, 1)
	table := tableTheme{
		tableHeaderStyle:    cellStyle.Foreground(lipgloss.Color(getThemeColor("table_header"))),
		defaultAliasStyle:   cellStyle.Foreground(lipgloss.Color(getThemeColor("default_alias"))),
		defaultHostStyle:    cellStyle.Foreground(lipgloss.Color(getThemeColor("default_host"))),
		defaultGroupStyle:   cellStyle.Foreground(lipgloss.Color(getThemeColor("default_group"))),
		selectedIconStyle:   cellStyle.Foreground(lipgloss.Color(getThemeColor("selected_icon"))).Bold(true),
		selectedAliasStyle:  cellStyle.Foreground(lipgloss.Color(getThemeColor("selected_alias"))).Bold(true),
		selectedHostStyle:   cellStyle.Foreground(lipgloss.Color(getThemeColor("selected_host"))).Bold(true),
		selectedGrouplStyle: cellStyle.Foreground(lipgloss.Color(getThemeColor("selected_group"))).Bold(true),
		defaultBorderStyle:  baseStyle.Foreground(lipgloss.Color(getThemeColor("default_border"))).Faint(true),
		selectedBorderStyle: baseStyle.Foreground(lipgloss.Color(getThemeColor("selected_border"))).Bold(true),
		detailsNameStyle:    cellStyle.Foreground(lipgloss.Color(getThemeColor("details_name"))),
		detailsValueStyle:   cellStyle.Foreground(lipgloss.Color(getThemeColor("details_value"))),
		detailsBorderStyle:  baseStyle.Foreground(lipgloss.Color(getThemeColor("details_border"))).Faint(true),
	}
	return &promptTheme{
		HideLabel:       true,
		Help:            getDefaultHelpTipsTemplate(),
		Shortcuts:       getDefaultShortcutsTemplate(),
		ItemsRenderer:   table.renderItems,
		DetailsRenderer: table.renderDetails,
	}
}

func getPromptTheme() *promptTheme {
	switch strings.ToLower(userConfig.promptThemeLayout) {
	case "tiny":
		return getTinyTheme()
	case "simple":
		return getSimpleTheme()
	case "cyberpunk":
		return getCyberpunkTheme()
	case "table":
		return getTableTheme()
	default:
		userConfig.promptThemeLayout = "tiny"
		return getTinyTheme()
	}
}
