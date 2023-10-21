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

	"golang.org/x/term"
)

func execTools(args *sshArgs) int {
	switch {
	case args.Ver:
		fmt.Println(args.Version())
		return 0
	case args.EncSecret:
		return execEncodeSecret()
	}
	return -1
}

func execEncodeSecret() int {
	for {
		fmt.Print("Password or secret to be encoded: ")
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Print("\r\n")
		if err != nil {
			fmt.Printf("%v\r\n", err)
			return -1
		}
		if len(secret) == 0 {
			continue
		}
		encoded, err := encodeSecret(secret)
		if err != nil {
			fmt.Printf("%v\r\n", err)
			return -2
		}
		fmt.Printf("Encoded secret for configuration: %s\r\n", encoded)
		return 0
	}
}
