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
	kv.KVStore

	Cfg Config
}

var _ auth.IAuthenticator = &AuthKV{}

func NewKVAuth(cfg Config) (auth.IAuthenticator, error) {
	store, errStore := badger.NewBStoreInMem(log.NewLogger(log.DEBUG, os.Stdout, true))
	if errStore != nil {
		return nil, errStore
	}

	return &AuthKV{
		KVStore: store,

		Cfg: cfg,
	}, nil
}

// interface methods to be implemented
func (k *AuthKV) Create(auth.Customer) error {
	return nil
}

func (k *AuthKV) UpdateEmail(custID int64, newEmail string) error           { return nil }
func (k *AuthKV) UpdateName(custID int64, firstName, lastName string) error { return nil }
func (k *AuthKV) UpdatePassword(custID int64, p string) error               { return nil }
func (k *AuthKV) Authenticate(email, password string) error                 { return nil }
func (k *AuthKV) LostPasswordRequest(email string) (string, error)          { return "", nil }
