package pbe

import (
	"flag"
	"fmt"
	"os"

	pbe "."
)

func Example() {
	email := flag.String("email", "", "email address")
	pass := flag.String("pass", "", "password")
	encrypt := flag.Bool("encrypt", false, "encrypt")
	decrypt := flag.Bool("decrypt", false, "decrypt")
	iter := flag.Int("iter", 5000, "number of iterations of hash function (defaults to 5000)")

	flag.Parse()

	if *email == "" {
		exit("Please specify an -email")
	}
	if *pass == "" {
		exit("Please specify a -pass")
	}
	if !*encrypt && !*decrypt {
		exit("Please specify either -encrypt or -decrypt")
	}

	data := flag.Arg(0)
	if data == "" {
		exit("Please specify data to encrypt/decrypt")
	}

	box := pbe.New([]byte(*email), []byte(*pass), *iter)

	if *encrypt {
		fmt.Fprintf(os.Stdout, "%s\n", box.EncryptToString([]byte(data)))
	} else {
		decrypted, err := box.DecryptFromString(data)
		if err != nil {
			fail("Unable to decrypt", err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", string(decrypted))
	}
}

func exit(msg string) {
	fmt.Fprint(os.Stderr, msg+"\n")
	flag.Usage()
	os.Exit(1)
}

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, msg+": %s\n", err)
	os.Exit(2)
}
