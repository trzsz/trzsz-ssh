/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

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
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	redColor     = lipgloss.Color("1")
	greenColor   = lipgloss.Color("2")
	yellowColor  = lipgloss.Color("3")
	blueColor    = lipgloss.Color("4")
	magentaColor = lipgloss.Color("5")
	cyanColor    = lipgloss.Color("6")
)

func hideCursor(writer io.Writer) {
	_, _ = writer.Write([]byte("\x1b[?25l"))
}

func showCursor(writer io.Writer) {
	_, _ = writer.Write([]byte("\x1b[?25h"))
}

type toolsProgress struct {
	prefix        string
	totalSize     int
	currentStep   int
	progressTimer *time.Timer
}

func newToolsProgress(tool, name string, totalSize int) *toolsProgress {
	hideCursor(os.Stderr)
	p := &toolsProgress{prefix: fmt.Sprintf("[%s] %s", tool, name), totalSize: totalSize}
	p.progressTimer = time.AfterFunc(100*time.Millisecond, p.showProgress)
	return p
}

func (p *toolsProgress) writeMessage(format string, a ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\r\033[0;36m%s %s\033[0m", p.prefix, format), a...)
}

func (p *toolsProgress) addStep(delta int) {
	p.currentStep += delta
	if p.currentStep >= p.totalSize {
		p.writeMessage("%d%%", 100)
		p.stopProgress()
	}
}

func (p *toolsProgress) showProgress() {
	percentage := int(math.Round(float64(p.currentStep) * 100 / float64(p.totalSize)))
	if percentage >= 100 {
		return
	}
	p.writeMessage("%d%%", percentage)
	p.progressTimer = time.AfterFunc(time.Second, p.showProgress)
}

func (p *toolsProgress) stopProgress() {
	if p.progressTimer == nil {
		return
	}
	p.progressTimer.Stop()
	p.progressTimer = nil
	p.writeMessage("\r\n")
	showCursor(os.Stderr)
}

func toolsInfo(tool, format string, a ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;36m[%s] %s\033[0m\r\n", tool, format), a...)
}

func toolsWarn(tool, format string, a ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;33m[%s] %s\033[0m\r\n", tool, format), a...)
}

func toolsSucc(tool, format string, a ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;32m[%s] %s\033[0m\r\n", tool, format), a...)
}

func toolsErrorExit(format string, a ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;31m%s\033[0m\r\n", format), a...)
	os.Exit(-1)
}

func printToolsHelp(title string) {
	fmt.Print(lipgloss.NewStyle().Bold(true).Foreground(greenColor).Render(title) + "\r\n")
	fmt.Print(lipgloss.NewStyle().Faint(true).Render(getText("tools/help")) + "\r\n\r\n")
}

type inputValidator struct {
	validate func(string) error
}

type textInputModel struct {
	promptLabel  string
	defaultValue string
	helpMessage  string
	textInput    textinput.Model
	validator    *inputValidator
	done         bool
	quit         bool
	err          error
}

func (m *textInputModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m *textInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			m.quit = true
			return m, tea.Quit
		case tea.KeyCtrlW:
			m.textInput.SetValue("")
			return m, nil
		case tea.KeyEnter:
			err := m.validator.validate(m.getValue())
			if err != nil {
				m.err = err
				return m, nil
			}
			m.done = true
			return m, tea.Quit
		case tea.KeyRunes, tea.KeySpace:
			m.err = nil
		}
	case error:
		m.err = msg
		return m, nil
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m *textInputModel) View() string {
	if m.done {
		return fmt.Sprintf("%s%s%s\r\n\r\n", lipgloss.NewStyle().Foreground(greenColor).Render(m.promptLabel),
			lipgloss.NewStyle().Faint(true).Render(": "), m.getValue())
	}

	var builder strings.Builder
	builder.WriteString(lipgloss.NewStyle().Foreground(cyanColor).Render(m.promptLabel))
	if m.defaultValue != "" {
		builder.WriteByte('(')
		builder.WriteString(lipgloss.NewStyle().Foreground(magentaColor).Render(m.defaultValue))
		builder.WriteByte(')')
	}
	if !m.quit {
		builder.WriteString(m.textInput.View())
	}
	builder.WriteString("\r\n")
	if m.err != nil {
		builder.WriteString(lipgloss.NewStyle().Foreground(redColor).Render(m.err.Error()))
	} else if m.helpMessage != "" {
		builder.WriteString(lipgloss.NewStyle().Faint(true).Render(m.helpMessage))
	}
	return builder.String()
}

func (m *textInputModel) getValue() string {
	value := m.textInput.Value()
	if value == "" && m.defaultValue != "" {
		return m.defaultValue
	}
	return strings.TrimSpace(value)
}

func promptTextInput(promptLabel, defaultValue, helpMessage string, validator *inputValidator) string {
	textInput := textinput.New()
	textInput.Prompt = ": "
	textInput.Focus()
	m, err := tea.NewProgram(&textInputModel{
		promptLabel:  promptLabel,
		defaultValue: defaultValue,
		helpMessage:  helpMessage,
		textInput:    textInput,
		validator:    validator,
	}).Run()

	if model, ok := m.(*textInputModel); err == nil && ok {
		if model.quit {
			os.Exit(0)
		}
		return model.getValue()
	}
	toolsErrorExit("input error: %v", err)
	return ""
}

func promptBoolInput(promptLabel, helpMessage string, defaultValue bool) bool {
	var defaultLabel string
	if defaultValue {
		defaultLabel = "Y/n"
	} else {
		defaultLabel = "y/N"
	}
	input := promptTextInput(promptLabel, defaultLabel, helpMessage,
		&inputValidator{func(input string) error {
			switch strings.ToLower(input) {
			case "", "y", "yes", "n", "no", "y/n":
				return nil
			default:
				return fmt.Errorf("invalid input")
			}
		}})
	switch strings.ToLower(input) {
	case "", "y/n":
		return defaultValue
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		toolsErrorExit("unknown bool input: %s", input)
		return false
	}
}

type passwordModel struct {
	promptLabel   string
	helpMessage   string
	passwordInput string
	validator     *inputValidator
	cursorVisible bool
	done          bool
	quit          bool
	err           error
}

type tickMsg time.Time

func tickEvery(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *passwordModel) Init() tea.Cmd {
	return tickEvery(500 * time.Millisecond)
}

func (m *passwordModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			m.quit = true
			return m, tea.Quit
		case tea.KeyCtrlW:
			m.passwordInput = ""
			return m, nil
		case tea.KeyEnter:
			err := m.validator.validate(m.passwordInput)
			if err != nil {
				m.err = err
				return m, nil
			}
			m.done = true
			return m, tea.Quit
		case tea.KeyBackspace:
			if len(m.passwordInput) > 0 {
				m.passwordInput = m.passwordInput[:len(m.passwordInput)-1]
			}
		case tea.KeyRunes, tea.KeySpace:
			if len(msg.Runes) > 0 && msg.Runes[0] != 0 {
				m.passwordInput += string(msg.Runes)
			}
			m.err = nil
		}
	case error:
		m.err = msg
		return m, nil
	case tickMsg:
		m.cursorVisible = !m.cursorVisible
		return m, tickEvery(500 * time.Millisecond)
	}
	return m, nil
}

func (m *passwordModel) View() string {
	if m.done {
		return fmt.Sprintf("%s%s%s\r\n\r\n", lipgloss.NewStyle().Foreground(greenColor).Render(m.promptLabel),
			lipgloss.NewStyle().Faint(true).Render(": "), strings.Repeat("*", len(m.passwordInput)))
	}

	var builder strings.Builder
	builder.WriteString(lipgloss.NewStyle().Foreground(cyanColor).Render(m.promptLabel))
	builder.WriteString(": ")
	for i := 0; i < len(m.passwordInput); i++ {
		builder.WriteByte('*')
	}
	if !m.quit && m.cursorVisible {
		builder.WriteRune('█')
	} else {
		builder.WriteRune(' ')
	}
	builder.WriteString("\r\n")
	if m.err != nil {
		builder.WriteString(lipgloss.NewStyle().Foreground(redColor).Render(m.err.Error()))
	} else if m.helpMessage != "" {
		builder.WriteString(lipgloss.NewStyle().Faint(true).Render(m.helpMessage))
	}
	return builder.String()
}

func promptPassword(promptLabel, helpMessage string, validator *inputValidator) string {
	m, err := tea.NewProgram(&passwordModel{
		promptLabel: promptLabel,
		helpMessage: helpMessage,
		validator:   validator,
	}).Run()

	if model, ok := m.(*passwordModel); err == nil && ok {
		if model.quit {
			os.Exit(0)
		}
		return model.passwordInput
	}
	toolsErrorExit("input error: %v", err)
	return ""
}

type listModel struct {
	promptLabel string
	helpMessage string
	cursor      int
	items       []string
	done        bool
	quit        bool
}

func (m *listModel) Init() tea.Cmd {
	return nil
}

func (m *listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "ctrl+c":
			m.quit = true
			return m, tea.Quit
		case "j", "tab", "down":
			m.cursor++
			if m.cursor >= len(m.items) {
				m.cursor = 0
			}
		case "k", "shift+tab", "up":
			m.cursor--
			if m.cursor < 0 {
				m.cursor = len(m.items) - 1
			}
		case "enter":
			m.done = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *listModel) View() string {
	if m.done {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(lipgloss.NewStyle().Foreground(cyanColor).Render(m.promptLabel+":") + "\r\n")
	if m.helpMessage != "" {
		builder.WriteString(lipgloss.NewStyle().Faint(true).Render(m.helpMessage) + "\r\n")
	}
	for i, item := range m.items {
		if i == m.cursor {
			builder.WriteString(lipgloss.NewStyle().Foreground(magentaColor).
				Render(fmt.Sprintf("> %s", item)) + "\r\n")
		} else {
			builder.WriteString(lipgloss.NewStyle().Render(fmt.Sprintf("  %s", item)) + "\r\n")
		}
	}
	builder.WriteString(lipgloss.NewStyle().Faint(true).
		Render("Use ↓ ↑ j k or tab to navigate, Enter to choose.") + "\r\n")
	return builder.String()
}

func promptList(promptLabel, helpMessage string, listItems []string) string {
	m, err := tea.NewProgram(&listModel{
		promptLabel: promptLabel,
		helpMessage: helpMessage,
		items:       listItems,
	}).Run()

	if model, ok := m.(*listModel); err == nil && ok {
		if model.quit {
			os.Exit(0)
		}
		return model.items[model.cursor]
	}
	toolsErrorExit("input error: %v", err)
	return ""
}

func isFileNotExistOrEmpty(path string) bool {
	stat, err := os.Stat(path)
	if os.IsNotExist(err) {
		return true
	} else if err != nil {
		return false
	}
	return stat.Size() == 0
}

// execLocalTools execute local tools if necessary
//
// return true to quit with return code
// return false to continue ssh login
func execLocalTools(argv []string, args *sshArgs) (int, bool) {
	switch {
	case args.Ver:
		fmt.Println(args.Version())
		return 0, true
	case args.EncSecret:
		return execEncodeSecret()
	case args.NewHost || len(argv) == 0 && isFileNotExistOrEmpty(userConfig.configPath):
		return execNewHost(args)
	default:
		return 0, false
	}
}

// execRemoteTools execute remote tools if necessary
func execRemoteTools(args *sshArgs, client SshClient) {
	switch {
	case args.InstallTrzsz:
		execInstallTrzsz(args, client)
	}
}
