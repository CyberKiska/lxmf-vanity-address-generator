package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
)

type publicResult struct {
	Status          string   `json:"status"`
	Address         string   `json:"address,omitempty"`
	IdentityHash    string   `json:"identity_hash,omitempty"`
	X25519Public    string   `json:"x25519_public,omitempty"`
	Ed25519Public   string   `json:"ed25519_public,omitempty"`
	PublicKey       string   `json:"public_key,omitempty"`
	VerifiedFiles   []string `json:"verified_files"`
	UnverifiedFiles []string `json:"unverified_files"`
	Deviations      []string `json:"deviations"`
	Attempts        uint64   `json:"attempts"`
	ElapsedSeconds  float64  `json:"elapsed_seconds"`
	Generator       string   `json:"generator"`
	Version         string   `json:"version"`
	Error           string   `json:"error,omitempty"`
}

func newPublicResult(cfg config) publicResult {
	return publicResult{Status: "failed", VerifiedFiles: []string{}, UnverifiedFiles: []string{}, Deviations: []string{}, Generator: cfg.generator, Version: buildVersion()}
}
func (r *publicResult) identity(identity *Identity) {
	r.Address = hex.EncodeToString(identity.Address[:])
	r.IdentityHash = hex.EncodeToString(identity.Hash[:])
	r.X25519Public = hex.EncodeToString(identity.X25519Public[:])
	r.Ed25519Public = hex.EncodeToString(identity.Ed25519Public[:])
	r.PublicKey = r.X25519Public + r.Ed25519Public
}
func writeResult(writer io.Writer, structured bool, result *publicResult, text string) error {
	data := []byte(text)
	if structured {
		var err error
		data, err = json.Marshal(result)
		if err != nil {
			return err
		}
		data = append(data, '\n')
	}
	n, err := writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}
