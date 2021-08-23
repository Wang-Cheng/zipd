package main

import (
	"fmt"
	"github.com/wang-cheng/zip"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <zip file> <password>\n", os.Args[0])
		return
	}
	name := os.Args[1]
	password := os.Args[2]
	ok, err := zipDecTest(name, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		return
	}
	if ok {
		//fmt.Println("password is ok")
	} else {
		//fmt.Println("password invalid")
	}
}

func zipDecTest(name string, password string) (bool, error) {
	zipr, err := zip.OpenReader(name)
	if err != nil {
		return false, err
	}
	for _, f := range zipr.File {
		info := f.FileInfo()
		if info.IsDir() {
			fmt.Printf("%s is directory\n", f.Name)
			continue
		}
		if !f.IsEncrypted() {
			fmt.Printf("%s not encrypted\n", f.Name)
			continue
		}
		if !f.IsZipCrypto() {
			fmt.Printf("%s not zipcrypto\n", f.Name)
			continue
		}
		r, err := f.OpenRaw()
		if err != nil {
			fmt.Printf("%s open fail, err=%v\n", f.Name, err)
			continue
		}
		header := make([]byte, zip.ZipCryptoHeaderLen)
		n, err := r.Read(header)
		if err != nil {
			fmt.Printf("%s read fail, err=%v\n", f.Name, err)
			continue
		}
		if n != zip.ZipCryptoHeaderLen {
			fmt.Printf("%s read not expected length, n=%d\n", f.Name, n)
			continue
		}
		t := zip.NewZipCryptoTrier(header, [2]byte{byte(f.ModifiedTime & 0xff), byte((f.ModifiedTime >> 8) & 0xff)})
		ok := t.Try([]byte(password))
		if !ok {
			fmt.Printf("%s password invalid\n", f.Name)
			continue
		}
		fmt.Printf("%s password ok\n", f.Name)
	}
	return false, nil
}
