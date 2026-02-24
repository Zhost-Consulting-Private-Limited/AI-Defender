package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

type FileIntegrityEvent struct {
	Path         string
	Action       string
	SHA256Before string
	SHA256After  string
}

func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func BuildFIMEvent(path, action, before string) (FileIntegrityEvent, error) {
	after, err := HashFile(path)
	if err != nil {
		return FileIntegrityEvent{}, err
	}
	return FileIntegrityEvent{Path: path, Action: action, SHA256Before: before, SHA256After: after}, nil
}
