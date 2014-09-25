package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

var configFile *string = flag.String("config-file", "", "Location of the config file")

func importConfig() *Config {
	if len(*configFile) == 0 {
		fmt.Printf("Nothing in the config file...")
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
		*configFile = filepath.Join(homeDir, ".xmpp-gui")
	}

	fmt.Printf("Parsing the config file...")
	config, err := ParseConfig(*configFile)
	
	if err != nil {
		fmt.Printf("Failed to parse config file %s: ", err.Error())
		//config = new(Config)
		// if !enroll(config, term) {
		// 	return
		//}
		config.filename = *configFile
		config.Save()
	}

	return config
}
