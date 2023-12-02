/*
MIT License

Copyright (c) 2023 Lonny Wong <lonnywong@qq.com>
Copyright (c) 2023 [Contributors](https://github.com/trzsz/trzsz-ssh/graphs/contributors)

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

func toolsErrorExit(format string, a ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("\033[0;31m%s\033[0m\r\n", format), a...)
	os.Exit(-1)
}

func printToolsHelp(title string) {
	fmt.Print(lipgloss.NewStyle().Bold(true).Foreground(greenColor).Render(title) + "\r\n")
	fmt.Print(lipgloss.NewStyle().Faint(true).Render(
		"-- 可以直接按回车键接受括号内提供的默认选项，使用 Ctrl+C 可以立即退出") + "\r\n\r\n")
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
	builder.WriteString(m.textInput.View())
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
			m.passwordInput += string(msg.Runes)
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
	if m.cursorVisible {
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

func execTools(args *sshArgs) (int, bool) {
	switch {
	case args.Ver:
		fmt.Println(args.Version())
		return 0, true
	case args.EncSecret:
		return execEncodeSecret()
	case args.NewHost:
		return execNewHost(args)
	default:
		return 0, false
	}
}

func execEncodeSecret() (int, bool) {
	secret := promptPassword("Password or secret to be encoded", "",
		&inputValidator{func(secret string) error {
			if secret == "" {
				return fmt.Errorf("empty password or secret")
			}
			return nil
		}})
	encoded, err := encodeSecret([]byte(secret))
	if err != nil {
		toolsErrorExit("encode secret failed: %v", err)
	}
	fmt.Printf("%s%s%s\r\n\r\n",
		lipgloss.NewStyle().Foreground(greenColor).Render("Encoded secret for configuration"),
		lipgloss.NewStyle().Faint(true).Render(": "), encoded)
	return 0, true
}
