// 30 august 2014

package main

import (
//	"fmt"
	"flag"	
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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

	// Pull accounts from config file
	for i, account := range config.Accounts {
		acctName := strings.Join([]string{account.Name, account.Server}, "@")
		accounts[i] = DisplayAccount{false, acctName}
	}	

	// Populate table
	accountTable := ui.NewTable(reflect.TypeOf(accounts[0]))
	accountTable.Lock()
	e := accountTable.Data().(*[]DisplayAccount)
	*e = accounts
	accountTable.Unlock()

	// Assemble button stack
	addButton := ui.NewButton("Add")
	modifyButton := ui.NewButton("Modify")
	deleteButton := ui.NewButton("Delete")

	// Set up channel for sending data between windows
	done := make(chan Account)

	// When "Delete" is clicked, remove selected account
	deleteButton.OnClicked(func() {
		sel := accountTable.Selected()
		cfgAccts := config.Accounts

		// Delete the account from the config file
		config.Accounts = append(cfgAccts[:sel], cfgAccts[sel+1:]...)
		config.Save()

		// Delete the account from the table by building a new slice omitting it
		accountTable.Lock()
		tblAccts := accountTable.Data().(*[]DisplayAccount)
		aa := *tblAccts
		*tblAccts = append(aa[:sel], aa[sel+1:]...)
		accountTable.Unlock()
	})

	// When "Add" is clicked, open window to enter new account info
	addButton.OnClicked(func() {
		//Open the edit window and wait for a result
		editAccount(done)

		// Update accounts list concurrently once we hear back from the edit window
		go func() {
			acct := <-done

			// Add new account to config.Accounts
			config.Accounts = append(config.Accounts, acct)
			config.Save()

			// Update the accounts list
			accounts := make([]DisplayAccount, len(config.Accounts))
			
			for i, account := range config.Accounts {
				acctName := strings.Join([]string{account.Name, account.Server}, "@")
				accounts[i] = DisplayAccount{false, acctName}
			}	

			accountTable.Lock()
			e := accountTable.Data().(*[]DisplayAccount)
			*e = accounts
			accountTable.Unlock()
		}()
	})

	// Put the interface together
	buttons := ui.NewHorizontalStack(
		addButton,
		modifyButton,
		deleteButton)

	accountsInterface := ui.NewVerticalStack(
		accountTable,
		buttons)

	accountsInterface.SetStretchy(0)

	// Build/display the window
	acctWin := ui.NewWindow("Accounts", 400, 500, accountsInterface)

	acctWin.OnClosing(func() bool {
		ui.Stop()
		return true
	})

	acctWin.Show()
}

func editAccount(done chan Account) {
	// Assemble text fields
	username := ui.NewTextField()
	username.SetText("e.g. 'esnowden'")

	server := ui.NewTextField()
	server.SetText("e.g. 'ccc.de'")

	password := ui.NewPasswordField()
	password.SetText("password1234")

	textFields := ui.NewVerticalStack(
		ui.NewStandaloneLabel("Username"),
		username,
		ui.NewStandaloneLabel("Server"),
		server,
		ui.NewStandaloneLabel("Password"),		
		password)

	// Assemble button stack
	saveButton := ui.NewButton("Save")
	cancelButton := ui.NewButton("Cancel")

	buttons := ui.NewHorizontalStack(
		saveButton,
		cancelButton)

	editAccountInterface := ui.NewVerticalStack(
		textFields,
		buttons)

	editAccountInterface.SetStretchy(0)

	// Build and display window
	editWin := ui.NewWindow("Edit Account", 400, 400, editAccountInterface)

/*
	editWin.OnClosing(func() bool {
		return true
	})
*/

	//Save a new account
	saveButton.OnClicked(func() {
		//Validate the data (TODO: use the fields' methods for this)
		validUsername := regexp.MustCompile("[^\x00-\x20\x22\x26\x27\x2F\x3A\x3C\x3E\x40\x7F]+")
//		validDomain := regexp.MustCompile("(\w{2,}\.\w{2,3}\.\w{2,3}|\w{2,}\.\w{2,3})$")

		if strings.Trim(username.Text(), " ") == "" {
			username.Invalid("You must enter a username")
		} else if validUsername.MatchString(username.Text()) == false {
			username.Invalid("Username contains invalid characters")
//		} else if validDomain.MatchString(server.Text()) == false {
//			server.Invalid("Server contains invalid characters")
		} else {
			//Instantiate a new account and grow config.Accounts to add it
			acct := Account{Name: username.Text(), Server: server.Text(), Password: password.Text()}
			editWin.Hide()
			done <- acct
		}
	})

	cancelButton.OnClicked(func() {
		editWin.Hide()
	})

	editWin.Show()
}

func main() {
	go ui.Do(listAccounts)
	err := ui.Go()
	if err != nil {
		panic(err)
	}
}
