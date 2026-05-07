package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func Run() error {
	a := app.NewWithID("task1-1.auth-client")
	w := a.NewWindow("GM Password Auth Client")
	w.Resize(fyne.NewSize(720, 460))

	serverEntry := widget.NewEntry()
	serverEntry.SetText("http://127.0.0.1:8080")
	serverEntry.SetPlaceHolder("http://127.0.0.1:8080")

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("username")
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("password")

	statusEntry := widget.NewMultiLineEntry()
	statusEntry.SetMinRowsVisible(10)
	statusEntry.Wrapping = fyne.TextWrapWord
	statusEntry.Disable()
	appendStatus := func(msg string) {
		prefix := time.Now().Format("15:04:05")
		line := fmt.Sprintf("[%s] %s", prefix, msg)
		if statusEntry.Text == "" {
			statusEntry.SetText(line)
			return
		}
		statusEntry.SetText(statusEntry.Text + "\n" + line)
	}

	var registerButton *widget.Button
	var loginButton *widget.Button
	setBusy := func(busy bool) {
		if busy {
			registerButton.Disable()
			loginButton.Disable()
			return
		}
		registerButton.Enable()
		loginButton.Enable()
	}

	runAction := func(action string, fn func(*APIClient, string, []byte) error) {
		server := strings.TrimSpace(serverEntry.Text)
		username := strings.TrimSpace(usernameEntry.Text)
		password := []byte(passwordEntry.Text)

		if username == "" || len(password) == 0 {
			appendStatus("username and password are required")
			return
		}

		appendStatus(action + " started")
		setBusy(true)
		go func() {
			defer wipeBytes(password)
			client := NewAPIClient(server)
			err := fn(client, username, password)
			fyne.Do(func() {
				defer setBusy(false)
				if err != nil {
					appendStatus(action + " failed: " + err.Error())
					return
				}
				appendStatus(action + " succeeded")
			})
		}()
	}

	registerButton = widget.NewButton("Register", func() {
		runAction("register", func(client *APIClient, username string, password []byte) error {
			return client.Register(username, append([]byte(nil), password...))
		})
	})

	loginButton = widget.NewButton("Login", func() {
		runAction("login", func(client *APIClient, username string, password []byte) error {
			return client.Login(username, append([]byte(nil), password...))
		})
	})

	form := container.NewVBox(
		widget.NewLabel("Server Address"),
		serverEntry,
		widget.NewLabel("Username"),
		usernameEntry,
		widget.NewLabel("Password"),
		passwordEntry,
		container.NewGridWithColumns(2, registerButton, loginButton),
		widget.NewLabel("Status"),
		statusEntry,
	)

	w.SetContent(container.NewPadded(form))
	appendStatus("ready")
	w.ShowAndRun()
	return nil
}
