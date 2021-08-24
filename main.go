package main

import (
	"bytes"
	"fmt"
	"github.com/wang-cheng/zip"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
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
func isGBK(data []byte) bool {
	length := len(data)
	var i int = 0
	for i < length {
		if data[i] <= 0x7f {
			//编码0~127,只有一个字节的编码，兼容ASCII码
			i++
			continue
		} else {
			//大于127的使用双字节编码，落在gbk编码范围内的字符
			if i+1 < length &&
				data[i] >= 0x81 &&
				data[i] <= 0xfe &&
				data[i+1] >= 0x40 &&
				data[i+1] <= 0xfe &&
				data[i+1] != 0xf7 {
				i += 2
				continue
			} else {
				return false
			}
		}
	}
	return true
}
func gbkToUtf8(data []byte) ([]byte, error) {
	gbkReader := bytes.NewReader(data)
	utf8Reader := transform.NewReader(gbkReader, simplifiedchinese.GBK.NewDecoder())
	return ioutil.ReadAll(utf8Reader)
}
func utf8String(s string) (string, error) {
	data := []byte(s)
	if isGBK(data) {
		data, err := gbkToUtf8(data)
		return string(data), err
	}
	return s, nil
}
func zipDecTest(name string, password string) (bool, error) {
	zipr, err := zip.OpenReader(name)
	if err != nil {
		return false, err
	}
	for _, f := range zipr.File {
		info := f.FileInfo()
		name, err := utf8String(f.Name)
		if err != nil {
			fmt.Printf("%s utf8 convert fail, err=%v", f.Name, err)
		}
		if info.IsDir() {
			fmt.Printf("%s is directory\n", name)
			continue
		}
		if !f.IsEncrypted() {
			fmt.Printf("%s not encrypted\n", name)
			continue
		}
		r, err := f.OpenRaw()
		if err != nil {
			fmt.Printf("%s open fail, err=%v\n", name, err)
			continue
		}
		if f.IsZipCrypto() {
			header := make([]byte, zip.ZipCryptoHeaderLen)
			n, err := r.Read(header)
			if err != nil {
				fmt.Printf("%s read fail, err=%v\n", name, err)
				continue
			}
			if n != zip.ZipCryptoHeaderLen {
				fmt.Printf("%s read not expected length, n=%d\n", name, n)
				continue
			}
			t := zip.NewZipCryptoTrier(header, [2]byte{byte(f.ModifiedTime & 0xff), byte((f.ModifiedTime >> 8) & 0xff)})
			ok := t.Try([]byte(password))
			if !ok {
				fmt.Printf("%s password invalid\n", name)
				continue
			}
			fmt.Printf("%s password ok\n", name)
		} else {
			keyLen := aesKeyLen(f.AesStrength)
			saltLen := keyLen / 2
			if saltLen == 0 {
				fmt.Printf("%s invalid aesStrength=%d", name, f.AesStrength)
				continue
			}
			saltpwvv := make([]byte, saltLen+2)
			if n, err := r.Read(saltpwvv); err != nil || n != len(saltpwvv) {
				fmt.Printf("%s read salt fail, n=%d, err=%v", name, n, err)
				continue
			}
			salt := saltpwvv[:saltLen]
			pwvv := saltpwvv[saltLen:]
			ok := checkAesPassword(salt, pwvv, keyLen, []byte(password))
			if !ok {
				fmt.Printf("%s password invalid\n", name)
				continue
			}
			fmt.Printf("%s password ok\n", name)
		}
	}
	return false, nil
}
