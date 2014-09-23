// 30 august 2014

package main

import (
	"fmt"
	"flag"	
	"os"
	"path/filepath"
	"reflect"
	"strings"
//	"sync"
	"github.com/andlabs/ui"
//	"github.com/agl/xmpp"
)

type DisplayAccount struct {
	Enabled bool
	Name    string
}

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

	//var wg sync.WaitGroup
	done := make(chan Account)

	delete_button.OnClicked(func() {
		sel := account_table.Selected()
		cas := config.Accounts

		account_table.Lock()
		accts := account_table.Data().(*[]DisplayAccount)
		aa := *accts
		fmt.Printf("Deleting %s from config...", aa[sel].Name)
		config.Accounts = append(cas[:sel], cas[sel+1:]...)
		config.Save()
		fmt.Printf("Deleting %s from table...", aa[sel].Name)
		*accts = append(aa[:sel], aa[sel+1:]...)
		account_table.Unlock()
	})

	add_button.OnClicked(func() {
		//Open the edit window and wait for a result
		editAccount(done)

		// Update accounts list concurrently once we hear back from the edit window
		go func() {
			acct := <-done

			//Add new account to config.Accounts
			config.Accounts = append(config.Accounts, acct)
			config.Save()

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

func editAccount(done chan Account) {
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
			acct := Account{Name: username.Text(), Server: server.Text(), Password: password.Text()}
			edit_w.Hide()
			done <- acct
		}
	})

	cancel_button.OnClicked(func() {
		edit_w.Hide()
	})

	edit_w.Show()
}

func main() {
	go ui.Do(listAccounts)
	err := ui.Go()
	if err != nil {
		panic(err)
	}
}
