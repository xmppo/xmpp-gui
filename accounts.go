package main

import (
	"reflect"
	"regexp"
	"strings"
	"github.com/andlabs/ui"
//	"github.com/agl/xmpp"
)

type DisplayAccount struct {
	Enabled bool
	Name    string
}

func listAccounts() {
	// Import the configuration
	config := importConfig();

	// Assemble table of accounts
	accounts := make([]DisplayAccount, len(config.Accounts))

	// Pull accounts from config file
	for i, account := range config.Accounts {
		enabled := account.Enabled
		acctName := strings.Join([]string{account.Name, account.Domain}, "@")
		accounts[i] = DisplayAccount{enabled, acctName}
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

	// When "Modify" is clicked, present selected account for editing
	modifyButton.OnClicked(func() {
		sel := accountTable.Selected()
		cfgAccts := config.Accounts

		if sel < 0 {
			return
		}

		// Retrieve selected account
		acct := cfgAccts[sel]
		
		// Open window to edit selected account
		editAccount(acct, done)

		go func() {
			// Get edited account
			editedAcct := <- done

			// Update the account
			config.Accounts[sel] = editedAcct
			config.Save()

			// Update the accounts list
			accounts := make([]DisplayAccount, len(config.Accounts))
			
			for i, account := range config.Accounts {
				acctName := strings.Join([]string{account.Name, account.Domain}, "@")
				accounts[i] = DisplayAccount{account.Enabled, acctName}
			}	

			// Update accountTable
			accountTable.Lock()
			e := accountTable.Data().(*[]DisplayAccount)
			*e = accounts
			accountTable.Unlock()
		}()
	})

	// When "Add" is clicked, open window to enter new account info
	addButton.OnClicked(func() {
		// Create an empty Account to pass to editAccount
		var account Account;

		// Open the edit window and wait for a result
		editAccount(account, done)

		// Update accounts list concurrently once we hear back from the edit window
		go func() {
			acct := <-done

			// Add new account to config.Accounts
			config.Accounts = append(config.Accounts, acct)
			config.Save()

			// Update the accounts list
			accounts := make([]DisplayAccount, len(config.Accounts))
			
			for i, account := range config.Accounts {
				acctName := strings.Join([]string{account.Name, account.Domain}, "@")
				accounts[i] = DisplayAccount{account.Enabled, acctName}
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

func editAccount(account Account, done chan Account) {
	// Initialize fields
	enabled := ui.NewCheckbox("Enabled")
	username := ui.NewTextField()
	domain := ui.NewTextField()
	password := ui.NewPasswordField()

	// If this is an existing account, populate the fields from the config file
	if len(account.Name) > 0 {
		enabled.SetChecked(account.Enabled)
		username.SetText(account.Name)
		domain.SetText(account.Domain)
		password.SetText(account.Password)		
	} else {
		enabled.SetChecked(false)
		username.SetText("e.g. 'esnowden'")
		domain.SetText("e.g. 'ccc.de'")
		password.SetText("password1234")
	}

	// Assemble input fields
	textFields := ui.NewVerticalStack(
		ui.NewStandaloneLabel("Enabled"),
		enabled,
		ui.NewStandaloneLabel("Username"),
		username,
		ui.NewStandaloneLabel("Domain"),
		domain,
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

	editWin.OnClosing(func() bool {
		return true
	})

	//Save a new account
	saveButton.OnClicked(func() {
		//Validate the data (TODO: use the fields' methods for this)
		validUsername := regexp.MustCompile("[^\x00-\x20\x22\x26\x27\x2F\x3A\x3C\x3E\x40\x7F]+")
//		validDomain := regexp.MustCompile("(\w{2,}\.\w{2,3}\.\w{2,3}|\w{2,}\.\w{2,3})$")

		if strings.Trim(username.Text(), " ") == "" {
			username.Invalid("You must enter a username")
		} else if validUsername.MatchString(username.Text()) == false {
			username.Invalid("Username contains invalid characters")
//		} else if validDomain.MatchString(domain.Text()) == false {
//			domain.Invalid("Domain contains invalid characters")
		} else {
			//Instantiate a new account and grow config.Accounts to add it
			acct := Account{Enabled: enabled.Checked(), Name: username.Text(), Domain: domain.Text(), Password: password.Text()}
			editWin.Hide()
			done <- acct
		}
	})

	cancelButton.OnClicked(func() {
		editWin.Hide()
	})

	editWin.Show()
}

/*
func main() {
	go ui.Do(listAccounts)
	err := ui.Go()
	if err != nil {
		panic(err)
	}
}
*/
