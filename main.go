// zstream -- encrypted TCP stream transport for ZFS replication
//
// Replaces netcat (nc) in ZFS send/receive pipelines.
// Uses AES-256-GCM authenticated encryption with a session key
// supplied by the caller (job-replicate.pl generates it per transfer).
//
// Usage:
//   Receiver (start first):
//     zfs receive -F tank/backup < <(zstream listen <port> <key>)
//     -- or --
//     zstream listen <port> <key> | zfs receive -F tank/backup
//
//   Sender:
//     zfs send tank@snap | zstream send <host> <port> <key>
//
// Key:
//   Any string (hex preferred). job-replicate.pl passes sha256_hex(time+ips+snap).
//   Key is hashed to 32 bytes with SHA-256 internally.
//
// Wire format:
//   [4 bytes BE chunk length][AES-256-GCM nonce 12 bytes][ciphertext][tag 16 bytes]
//   Each chunk is up to 64KB of plaintext, independently encrypted.
//   Chunk length covers nonce+ciphertext+tag (not plaintext length).
//   A zero-length chunk (4 zero bytes) signals end of stream.
//
// Build:
//   See zstream.info for per-platform build instructions.
//
// License: MIT

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const (
	chunkSize   = 65536 // 64 KB plaintext per chunk
	dialTimeout = 30 * time.Second
	version     = "1.0.0"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := strings.ToLower(os.Args[1])
	switch cmd {
	case "listen":
		if len(os.Args) != 4 {
			fmt.Fprintf(os.Stderr, "usage: zstream listen <port> <key>\n")
			os.Exit(1)
		}
		doListen(os.Args[2], os.Args[3])
	case "send":
		if len(os.Args) != 5 {
			fmt.Fprintf(os.Stderr, "usage: zstream send <host> <port> <key>\n")
			os.Exit(1)
		}
		doSend(os.Args[2], os.Args[3], os.Args[4])
	case "version", "--version", "-v":
		fmt.Printf("zstream %s\n", version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "zstream %s -- encrypted TCP stream transport for ZFS replication\n\n", version)
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  zstream listen <port> <key>          listen and decrypt to stdout\n")
	fmt.Fprintf(os.Stderr, "  zstream send   <host> <port> <key>   encrypt stdin and send\n")
	fmt.Fprintf(os.Stderr, "  zstream version                      print version\n\n")
	fmt.Fprintf(os.Stderr, "Example:\n")
	fmt.Fprintf(os.Stderr, "  # Receiver:\n")
	fmt.Fprintf(os.Stderr, "  zstream listen 9000 MYKEY | zfs receive -F tank/backup\n\n")
	fmt.Fprintf(os.Stderr, "  # Sender:\n")
	fmt.Fprintf(os.Stderr, "  zfs send tank@snap | zstream send 192.168.1.10 9000 MYKEY\n")
}

// deriveKey derives a 32-byte AES key from an arbitrary string via SHA-256.
func deriveKey(keystr string) []byte {
	h := sha256.Sum256([]byte(keystr))
	return h[:]
}

// newGCM creates an AES-256-GCM cipher from a key string.
func newGCM(keystr string) (cipher.AEAD, error) {
	key := deriveKey(keystr)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// doListen opens a TCP listener, accepts one connection, decrypts the stream
// and writes plaintext to stdout.
func doListen(port, keystr string) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		fatalf("listen :%s: %v", port, err)
	}
	defer ln.Close()

	logf("listening on :%s", port)

	conn, err := ln.Accept()
	if err != nil {
		fatalf("accept: %v", err)
	}
	defer conn.Close()
	ln.Close() // accept only one connection

	logf("connection from %s", conn.RemoteAddr())

	gcm, err := newGCM(keystr)
	if err != nil {
		fatalf("cipher init: %v", err)
	}

	total, err := decryptStream(conn, os.Stdout, gcm)
	if err != nil {
		fatalf("decrypt: %v", err)
	}
	logf("received %d bytes (plaintext)", total)
}

// doSend connects to host:port, encrypts stdin and sends the encrypted stream.
func doSend(host, port, keystr string) {
	addr := net.JoinHostPort(host, port)

	// Retry connect for up to 30s (receiver may not be ready yet)
	var conn net.Conn
	var err error
	deadline := time.Now().Add(dialTimeout)
	for {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			fatalf("connect %s: %v", addr, err)
		}
		logf("connect %s failed, retrying... (%v)", addr, err)
		time.Sleep(2 * time.Second)
	}
	defer conn.Close()

	logf("connected to %s", addr)

	gcm, err := newGCM(keystr)
	if err != nil {
		fatalf("cipher init: %v", err)
	}

	total, err := encryptStream(os.Stdin, conn, gcm)
	if err != nil {
		fatalf("encrypt: %v", err)
	}
	logf("sent %d bytes (plaintext)", total)
}

// encryptStream reads plaintext from r, encrypts in chunks and writes to w.
// Wire format per chunk: [4B length BE][12B nonce][ciphertext+16B GCM tag]
// End of stream: 4 zero bytes.
func encryptStream(r io.Reader, w io.Writer, gcm cipher.AEAD) (int64, error) {
	buf := make([]byte, chunkSize)
	var total int64

	for {
		n, readErr := io.ReadFull(r, buf)
		if n == 0 && readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return total, fmt.Errorf("read: %w", readErr)
		}
		if n == 0 {
			break
		}

		// Generate random nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return total, fmt.Errorf("nonce: %w", err)
		}

		// Encrypt chunk
		ciphertext := gcm.Seal(nonce, nonce, buf[:n], nil)
		// ciphertext = nonce + encrypted_data + tag

		// Write length prefix (4 bytes BE)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return total, fmt.Errorf("write len: %w", err)
		}

		// Write nonce + ciphertext + tag
		if _, err := w.Write(ciphertext); err != nil {
			return total, fmt.Errorf("write chunk: %w", err)
		}

		total += int64(n)

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	// Write end-of-stream marker: 4 zero bytes
	if _, err := w.Write([]byte{0, 0, 0, 0}); err != nil {
		return total, fmt.Errorf("write eos: %w", err)
	}

	return total, nil
}

// decryptStream reads encrypted chunks from r, decrypts and writes plaintext to w.
func decryptStream(r io.Reader, w io.Writer, gcm cipher.AEAD) (int64, error) {
	var total int64
	nonceSize := gcm.NonceSize()

	for {
		// Read 4-byte length prefix
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			return total, fmt.Errorf("read len: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf[:])

		// Zero length = end of stream
		if chunkLen == 0 {
			break
		}

		// Sanity check: max chunk = nonce + chunkSize + GCM tag (16)
		maxChunk := uint32(nonceSize + chunkSize + 16)
		if chunkLen > maxChunk {
			return total, fmt.Errorf("chunk too large: %d (max %d) -- wrong key?", chunkLen, maxChunk)
		}

		// Read nonce + ciphertext + tag
		chunk := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return total, fmt.Errorf("read chunk: %w", err)
		}

		if uint32(len(chunk)) < uint32(nonceSize) {
			return total, fmt.Errorf("chunk too short for nonce")
		}

		nonce := chunk[:nonceSize]
		ciphertext := chunk[nonceSize:]

		// Decrypt and authenticate
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return total, fmt.Errorf("decrypt/auth failed -- wrong key or corrupted data: %w", err)
		}

		if _, err := w.Write(plaintext); err != nil {
			return total, fmt.Errorf("write plaintext: %w", err)
		}

		total += int64(len(plaintext))
	}

	return total, nil
}

// logf writes a timestamped message to stderr (not stdout -- stdout is data).
func logf(format string, args ...interface{}) {
	ts := time.Now().Format("2006.01.02 15:04:05")
	fmt.Fprintf(os.Stderr, "%s  zstream  %s\n", ts, fmt.Sprintf(format, args...))
}

func fatalf(format string, args ...interface{}) {
	logf("ERROR "+format, args...)
	os.Exit(1)
}
