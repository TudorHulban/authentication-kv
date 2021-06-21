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

	l *log.Logger
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

func NewKVAuth(cfg *Config) (*AuthKV, error) {
	return &AuthKV{
		Config: *cfg,
		l:      log.NewLogger(log.DEBUG, os.Stdout, true),
	}, nil
}

// Create Method to create customer.
// Password is not hashed when passing the object. Salt would be overwritten.
func (k *AuthKV) Create(cust auth.Customer) error {
	if _, errExists := k.CustomerDetails(cust.EMail); errExists == nil {
		return auth.ErrEmailExists
	}

	salt := auth.GenerateSALT(10)
	cust.PasswordSalt = salt

	hash, errHash := auth.HASHPassword(cust.PasswordHash, cust.PasswordSalt, 14)
	if errHash != nil {
		return errHash
	}

	cust.PasswordHash = string(hash)

	return k.storeCustomer(cust)
}

func (k *AuthKV) storeCustomer(c auth.Customer) error {
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

func (k *AuthKV) UpdateName(email, firstName, lastName string) error {
	cust, errDet := k.CustomerDetails(email)
	if errDet != nil {
		return errDet
	}

	cust.FirstName = firstName
	cust.LastName = lastName

	return k.storeCustomer(*cust)
}

func (k *AuthKV) UpdatePassword(email, newPassword string) error {
	cust, errDet := k.CustomerDetails(email)
	if errDet != nil {
		return errDet
	}

	hash, errHash := auth.HASHPassword(newPassword, cust.PasswordSalt, 14)
	if errHash != nil {
		return errHash
	}

	cust.PasswordHash = string(hash)

	return k.storeCustomer(*cust)
}

func (k *AuthKV) Authenticate(email, password string) error {
	cust, errDet := k.CustomerDetails(email)
	if errDet != nil {
		return auth.ErrInternal
	}

	if !auth.CheckPasswordHash(password, cust.PasswordSalt, cust.PasswordHash) {
		return auth.ErrUnknownCredentials
	}

	return nil
}

// LostPasswordRequest Method checks if valid email. If yes returns temporary password.
func (k *AuthKV) LostPasswordRequest(email string) (string, error) {
	generatedPass := auth.RandomString(10)

	if errUpd := k.UpdatePassword(email, generatedPass); errUpd != nil {
		return "", errUpd // TODO: check if better return internal error for better security
	}

	return generatedPass, nil
}

func (k *AuthKV) Delete(email string) error {
	return k.Store.DeleteKVByK([]byte(email))
}

func (k *AuthKV) CustomerDetails(email string) (*auth.Customer, error) {
	cust, errGet := k.Store.GetVByK([]byte(email))
	if errGet != nil {
		return nil, errGet
	}

	var c auth.Customer
	errDecode := auth.Decoder(cust, &c)

	return &c, errDecode
}
