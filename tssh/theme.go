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

	"github.com/charmbracelet/lipgloss"
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
	return fmt.Sprintf(`{{ "Use ← ↓ ↑ → h j k l to navigate, / toggles search, ? toggles help" | %s }}`, getThemeColor("help_tips"))
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
		Details:   getDefaultDetailsTemplate(),
		Help:      getDefaultHelpTipsTemplate(),
		Shortcuts: getDefaultShortcutsTemplate(),
	}
}

func getSimpleTheme() *promptTheme {
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
		Details:   getDefaultDetailsTemplate(),
		Help:      getDefaultHelpTipsTemplate(),
		Shortcuts: getDefaultShortcutsTemplate(),
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
	if col == 0 {
		return t.selectedIconStyle
	}
	if host.Selected {
		switch col {
		case 1:
			return t.selectedAliasStyle
		case 2:
			return t.selectedHostStyle
		case 3:
			return t.selectedGrouplStyle
		}
	} else {
		switch col {
		case 1:
			return t.defaultAliasStyle
		case 2:
			return t.defaultHostStyle
		case 3:
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
	var data [][]string
	for _, item := range items {
		host := item.(*sshHost)
		icon := " "
		if host.Selected {
			icon = "✔"
		}
		data = append(data, []string{icon, host.Alias, host.Host, host.GroupLabels})
	}
	tbl := table.New().BorderRow(true).
		Headers("", "Alias", "Host Name", "Group Labels").Rows(data...).
		StyleFunc(func(row, col int) lipgloss.Style {
			var host *sshHost
			if row > 0 {
				host = items[row-1].(*sshHost)
			}
			return t.cellStyle(host, row, col)
		}).
		BorderStyleFunc(func(row, col int, borderType table.BorderType) lipgloss.Style {
			return t.borderStyle(idx, row, col, borderType)
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
	renderer := lipgloss.NewRenderer(os.Stderr)
	baseStyle := renderer.NewStyle()
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
	case "table":
		return getTableTheme()
	default:
		userConfig.promptThemeLayout = "tiny"
		return getTinyTheme()
	}
}
