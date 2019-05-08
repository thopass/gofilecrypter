// main file for AdvancedCrypter application

package main

import (
	"flag"
	"fmt"

	"github.com/thopass/gohello"
)

const VERSION_MAJOR = 3
const VERSION_MINOR = 1

func main() {
	gohello.PrintTitle("GoFileCrypter")
	gohello.PrintVersion(VERSION_MAJOR, VERSION_MINOR, 0)

	inFilename := flag.String("src", "", "Input file name")
	userPass := flag.String("pass", "", "Encryption password")
	action := flag.String("action", "", "Action: ( enc | dec )")

	flag.Parse()

	if *inFilename == "" || *userPass == "" || *action == "" {
		fmt.Println("Launch with '--help' for details")
		return
	}

	var appConfiguration Options

	if *action == "enc" {
		appConfiguration.operation = Encrypt
	} else if *action == "dec" {
		appConfiguration.operation = Decrypt
	} else {
		fmt.Println("Supported actions: ( enc | dec ) ")
		return
	}

	appConfiguration.sourceFile = *inFilename
	appConfiguration.password = []byte(*userPass)

	result := 0
	switch appConfiguration.operation {
	case Encrypt:
		result = startEncryption(appConfiguration)
		break
	case Decrypt:
		result = startDecryption(appConfiguration)
		break
	default:
		// this should never happen as operiation is checked above
		result = 1
	}

	if result == 1 {
		fmt.Println("Something gone wrong!")
		return
	} else {
		fmt.Println("All operation finished.")
	}
}
