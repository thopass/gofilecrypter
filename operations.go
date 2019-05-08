package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/thopass/gocryptlib"
)

var formatMarker = []byte{'T', 'H', 'P', 'S'}

const BUFFER_SIZE = 2048

func startEncryption(params Options) int {
	fmt.Println("Running encryption operation")
	vmajor, vminor := gocryptlib.GetVersion()
	fmt.Printf("Using tspgocrypt library v. %d.%d\n", vmajor, vminor)
	key := generateEncryptionKey()

	// try to open input file (defer closing if no error)
	inFile, err := os.Open(params.sourceFile)
	if err != nil {
		fmt.Println("Unable to open input file!")
		return 1
	}
	defer inFile.Close()

	// try to open output file (filename: "enc_" + input name)
	outFile, err := os.Create("enc_" + params.sourceFile)
	if err != nil {
		fmt.Println("Unable to open output file!")
		return 1
	}
	defer outFile.Close()

	// write file header
	// marker + version:
	_, err = outFile.Write(formatMarker)
	if err != nil {
		fmt.Println("Failed to write marker!")
		return 1
	}
	_, err = outFile.Write([]byte{VERSION_MAJOR})
	if err != nil {
		fmt.Println("Failed to write major version!")
		return 1
	}

	// prepare XORCrypter object for encryption handling
	encryptor := gocryptlib.GetXORCrypter()

	var buffer [16]byte
	// encrypt key with user password and save it to header
	// support only version 2: password hash used instead of plain passwor
	// md5sum and key used by application are both 16-byte long
	passHash := md5.Sum(params.password)
	buffer = key
	encryptor.Encrypt(buffer[0:len(key)], passHash[0:len(passHash)], 0)
	outFile.Write(buffer[0:len(key)])

	// WARNING: starting from this point all data written to file
	// are encrypted using generated key with continously incremented
	// globalCounter

	filenameLength := len(params.sourceFile)
	globalCounter := uint(0)
	dataReady := uint(0)
	// save filename length to file header
	// INFO: filename in most filesystems is not longer than 255 bytes
	// storing filename on 2 bytes cause leaking of first byte of enc key
	buffer[0] = byte(filenameLength & 0xff)
	dataReady++

	// save encrypted filename to file header
	for n := 0; n < filenameLength; n++ {
		index := dataReady & 0x0f
		buffer[index] = byte(params.sourceFile[n])

		if index == 15 {
			encryptor.Encrypt(buffer[0:len(buffer)], key[0:len(key)], globalCounter)
			outFile.Write(buffer[0:len(buffer)])
			globalCounter += 16
		}
		dataReady++
	}

	// save encrypted marker to file header (allows simple check on decryption)
	// TODO consider data XORing and writing to file in dedicated function
	for n := 0; n < len(formatMarker); n++ {
		index := dataReady & 0x0f
		buffer[index] = formatMarker[n]

		if index == 15 {
			encryptor.Encrypt(buffer[0:len(buffer)], key[0:len(key)], globalCounter)
			outFile.Write(buffer[0:16])
			globalCounter += 16
		}
		dataReady++
	}
	// write all remaining data from buffer

	dataReady &= 0x0f
	encryptor.Encrypt(buffer[0:dataReady], key[0:len(key)], globalCounter)
	outFile.Write(buffer[0:dataReady])
	globalCounter += dataReady

	// read input file (in chunks), encrypt and save to output
	var fileBuffer [BUFFER_SIZE]byte
	bytecount, _ := inFile.Read(fileBuffer[0:BUFFER_SIZE])
	for bytecount > 0 {
		// encrypt buffer
		encryptor.Encrypt(fileBuffer[0:bytecount], key[0:len(key)], globalCounter)
		globalCounter += uint(bytecount)
		// save it to output file
		outFile.Write(fileBuffer[0:bytecount])
		// read next chunk
		bytecount, _ = inFile.Read(fileBuffer[0:BUFFER_SIZE])
	}

	return 0
}

func startDecryption(params Options) int {
	fmt.Println("Running decryption operation")
	vmajor, vminor := gocryptlib.GetVersion()
	fmt.Printf("Using tspgocrypt library v. %d.%d\n", vmajor, vminor)

	// try to open input file (defer closing if no error)
	inFile, err := os.Open(params.sourceFile)
	if err != nil {
		fmt.Println("Unable to open input file!")
		return 1
	}
	defer inFile.Close()

	var buffer [16]byte
	// read only first 5 bytes: marker and version
	count, _ := inFile.Read(buffer[0:5])
	if count != 5 || bytes.Compare(buffer[0:4], formatMarker[0:4]) != 0 {
		fmt.Println("No proper maker read!")
		return 1
	} else {
		fmt.Println("Unencrypted marker found")
	}
	fileVersion := int(buffer[4])
	if fileVersion > VERSION_MAJOR {
		fmt.Println("File encrypted with unsupported tool version:",
			fileVersion)
	}
	fmt.Println("File encrypted with version:", fileVersion)

	// prepare XORCrypter object for decryption handling
	decryptor := gocryptlib.GetXORCrypter()
	var bytesCrypted uint

	count, _ = inFile.Read(buffer[0:16])
	// read password-encrypted encryption key
	if count != 16 {
		fmt.Println("Failed to read key from file!")
		return 1
	}
	// decrypt the key
	var key [16]byte
	switch fileVersion {
	case 1:
		key = buffer
		bytesCrypted = decryptor.Decrypt(key[0:len(key)], params.password, 0)
		break
	case 2, 3:
		passHash := md5.Sum(params.password)
		key = buffer
		bytesCrypted = decryptor.Decrypt(key[0:len(key)], passHash[0:len(key)], 0)
		break
	default:
		fmt.Println("File encrypted with unsupported tool version")
	}

	// fetch original filename length and decrypt it using key
	globalCounter := uint(0)
	var filenameLength int
	if fileVersion < 3 {
		count, _ = inFile.Read(buffer[0:2])
		if count != 2 {
			fmt.Println("Failed to read original filename!")
			return 1
		}

		bytesCrypted = decryptor.Decrypt(buffer[0:2], key[0:len(key)], globalCounter)
		filenameLength = int(buffer[0])
		filenameLength <<= 8
		filenameLength |= int(buffer[1])
		globalCounter += bytesCrypted
	} else {
		count, _ = inFile.Read(buffer[0:1])
		if count != 1 {
			fmt.Println("Failed to read original filename!")
			return 1

		}
		filenameLength = int(buffer[0] ^ key[globalCounter&0x0f])
		globalCounter++
	}

	var originalFilename string
	// first read N*16 bytes of filename
	for (filenameLength & 0xfff0) > 0 {
		count, _ = inFile.Read(buffer[0:16])
		if count != 16 {
			// something went wrong - possibly incorrect key
			fmt.Println("Failed to decrypt original filename!")
			return 1
		}

		bytesCrypted = decryptor.Decrypt(buffer[0:count], key[0:len(key)], globalCounter)
		globalCounter += bytesCrypted
		originalFilename += string(buffer[0:count])
	}
	filenameLength &= 0x000f
	if filenameLength > 0 {
		// one non-full block of filename have to be read
		count, _ = inFile.Read(buffer[0:filenameLength])
		if count != filenameLength {
			fmt.Println("Failed to decrypt original filename!")
			return 1
		}
		bytesCrypted = decryptor.Decrypt(buffer[0:count], key[0:len(key)], globalCounter)
		originalFilename += string(buffer[0:count])
		globalCounter += bytesCrypted
	}
	fmt.Println("Original filename:", originalFilename)

	// read and verify encrypted marker
	count, _ = inFile.Read(buffer[0:4])
	if count != 4 {
		fmt.Println("Failed to read encrypted marker!")
		return 1
	}
	bytesCrypted = decryptor.Decrypt(buffer[0:count], key[0:len(key)], globalCounter)
	globalCounter += bytesCrypted

	if bytes.Compare(formatMarker[0:4], buffer[0:4]) != 0 {
		fmt.Println("Marker decryption failed!")
		return 1
	} else {
		fmt.Println("Encrypted marker found and verified")
	}

	// create output file
	outFile, err := os.Create("dec_" + originalFilename)
	if err != nil {
		fmt.Println("Unable to open output file!")
		return 1
	}
	defer outFile.Close()

	// decrypt data in chunks and save to output file
	var fileBuffer [BUFFER_SIZE]byte
	count, _ = inFile.Read(fileBuffer[0:BUFFER_SIZE])
	for count > 0 {
		// decrypt (in fact XOR) buffer with key
		bytesCrypted = decryptor.Decrypt(fileBuffer[0:count], key[0:len(key)], globalCounter)
		globalCounter += bytesCrypted
		// save it to output file
		outFile.Write(fileBuffer[0:count])
		// read next chunk
		count, _ = inFile.Read(fileBuffer[0:BUFFER_SIZE])
	}

	return 0
}

func generateEncryptionKey() [16]byte {

	var result [16]byte
	rand.Seed(time.Now().Unix())

	for i := 0; i < len(result); i++ {
		result[i] = byte(rand.Intn(256))
	}

	return result
}
