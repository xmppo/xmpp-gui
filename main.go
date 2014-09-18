// 30 august 2014

package main

import (
//	"fmt"
	"flag"	
        "image"	
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"github.com/andlabs/ui"
//	"github.com/agl/xmpp"
)

type areaHandler struct {
	img		*image.RGBA
}

func (a *areaHandler) Paint(rect image.Rectangle) *image.RGBA {
	return a.img.SubImage(rect).(*image.RGBA)
}

type DisplayAccount struct {
	Enabled bool
	Name    string
}

func (a *areaHandler) Mouse(me ui.MouseEvent) {}
func (a *areaHandler) Key(ke ui.KeyEvent) bool { return false }

var configFile *string = flag.String("config-file", "", "Location of the config file")

func importConfig() *Config {
	if len(*configFile) == 0 {
		homeDir := os.Getenv("HOME")
		if len(homeDir) == 0 {
			// alert(term, "$HOME not set. Please either export $HOME or use the -config-file option.\n")
			// TODO throw error
		}
		persistentDir := filepath.Join(homeDir, "Persistent")
		if stat, err := os.Lstat(persistentDir); err == nil && stat.IsDir() {
			// Looks like Tails.
			homeDir = persistentDir
		}
		*configFile = filepath.Join(homeDir, ".xmpp-client-example")
	}

	config, err := ParseConfig(*configFile)
	
	if err != nil {
		// alert(term, "Failed to parse config file: "+err.Error())
		//config = new(Config)
		// if !enroll(config, term) {
		// 	return
		//}
		config.filename = *configFile
		config.Save()
	}

	return config
}

func listAccounts() {
	// Import the configuration
	config := importConfig();

	// Assemble table of accounts
	accounts := make([]DisplayAccount, len(config.Accounts))

	for i, account := range config.Accounts {
		accounts[i] = DisplayAccount{false, strings.Join([]string{account.Name, account.Server}, "@")}
	}	

	account_table := ui.NewTable(reflect.TypeOf(accounts[0]))
	account_table.Lock()
	e := account_table.Data().(*[]DisplayAccount)
	*e = accounts
	account_table.Unlock()

	// Assemble button stack
	add_button := ui.NewButton("Add")
	modify_button := ui.NewButton("Modify")
	delete_button := ui.NewButton("Delete")

	var wg sync.WaitGroup

	add_button.OnClicked(func() {
		//Create a new account
		var acct Account

		//Open the edit window and wait for a result
		wg.Add(1)
		go editAccount(&acct, &wg)

		// Update accounts list concurrently once we hear back from the edit window
		go func() {
			wg.Wait()

			//Add new account to config.Accounts
			config.Accounts = append(config.Accounts, acct)

			//Update the accounts list
			accounts := make([]DisplayAccount, len(config.Accounts))
			
			for i, account := range config.Accounts {
				accounts[i] = DisplayAccount{false, strings.Join([]string{account.Name, account.Server}, "@")}
			}	

			account_table.Lock()
			e := account_table.Data().(*[]DisplayAccount)
			*e = accounts
			account_table.Unlock()
		}()
	})

	buttons := ui.NewHorizontalStack(
		add_button,
		modify_button,
		delete_button)

	accounts_interface := ui.NewVerticalStack(
		account_table,
		buttons)

	accounts_interface.SetStretchy(0)

	acct_w := ui.NewWindow("Accounts", 400, 500, accounts_interface)
	acct_w.OnClosing(func() bool {
		ui.Stop()
		return true
	})
	acct_w.Show()
}

func editAccount(acct *Account, wg *sync.WaitGroup) {
	// Assemble text fields
	username := ui.NewTextField()
	username.SetText("e.g. 'esnowden'")

	server := ui.NewTextField()
	server.SetText("e.g. 'ccc.de'")

	password := ui.NewPasswordField()
	password.SetText("password1234")

	text_fields := ui.NewVerticalStack(
		ui.NewStandaloneLabel("Username"),
		username,
		ui.NewStandaloneLabel("Server"),
		server,
		ui.NewStandaloneLabel("Password"),		
		password)

	// Assemble button stack
	save_button := ui.NewButton("Save")
	cancel_button := ui.NewButton("Cancel")

	buttons := ui.NewHorizontalStack(
		save_button,
		cancel_button)

	edit_account_interface := ui.NewVerticalStack(
		text_fields,
		buttons)

	edit_account_interface.SetStretchy(0)

	edit_w := ui.NewWindow("Edit Account", 400, 400, edit_account_interface)

	edit_w.OnClosing(func() bool {
		//ui.Stop()
		return true
	})

	//Save a new account
	save_button.OnClicked(func() {
		//Validate the data (TODO: use the fields' methods for this)
		if username.Text() != "" && server.Text() != "" && password.Text() != "" {
			//Instantiate a new account and grow config.Accounts to add it
			*acct = Account{Name: username.Text(), Server: server.Text(), Password: password.Text()}
			wg.Done()
			edit_w.Hide()
		}
	})

	cancel_button.OnClicked(func() {
		wg.Done()
		edit_w.Hide()
	})

	// Literally the whole program crashes if this isn't there
	//fmt.Printf("Showing edit window...\n")

	edit_w.Show()
}

func main() {
	go ui.Do(listAccounts)
	err := ui.Go()
	if err != nil {
		panic(err)
	}
}
