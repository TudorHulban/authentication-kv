package authenticationkv

import (
	"os"

	"github.com/TudorHulban/authentication"
	"github.com/TudorHulban/kv"
	badger "github.com/TudorHulban/kv-badger"
	"github.com/TudorHulban/log"
)

type Config struct {
	Store kv.KVStore
}

type AuthKV struct {
	Config
}

var _ auth.IAuthenticator = &AuthKV{}

func ConfigBadger() (*Config, error) {
	store, errStore := badger.NewBStoreInMem(log.NewLogger(log.DEBUG, os.Stdout, true))
	if errStore != nil {
		return nil, errStore
	}

	return &Config{
		Store: store,
	}, nil
}

func NewKVAuth(cfg Config) (auth.IAuthenticator, error) {
	return &AuthKV{
		Config: cfg,
	}, nil
}

// interface methods to be implemented
func (k *AuthKV) Create(c auth.Customer) error {
	payload, errEnc := badger.Encoder(c)
	if errEnc != nil {
		return errEnc
	}

	value := kv.KV{
		Key:   []byte(c.EMail),
		Value: payload,
	}

	return k.Store.Set(value)
}

func (k *AuthKV) UpdateEmail(custID int64, newEmail string) error           { return nil }
func (k *AuthKV) UpdateName(custID int64, firstName, lastName string) error { return nil }
func (k *AuthKV) UpdatePassword(custID int64, p string) error               { return nil }
func (k *AuthKV) Authenticate(email, password string) error                 { return nil }
func (k *AuthKV) LostPasswordRequest(email string) (string, error)          { return "", nil }
