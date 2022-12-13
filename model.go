package authenticationkv

import (
	"fmt"
	"os"

	auth "github.com/TudorHulban/authentication"
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
func (k *AuthKV) Create(cust *auth.Customer) error {
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

func (k *AuthKV) storeCustomer(c *auth.Customer) error {
	payload, errEnc := badger.Encoder(c)
	if errEnc != nil {
		return TransformationError{
			Issue: errEnc,
		}
	}

	item := kv.KV{
		Key:   []byte(c.EMail),
		Value: payload,
	}

	return k.Store.Set(item)
}

func (k *AuthKV) UpdateName(email string, firstName, lastName *string) error {
	var haveUpdates bool

	if firstName != nil || lastName != nil {
		haveUpdates = true
	}

	if !haveUpdates {
		return nil
	}

	reconstructedCustomer, errDetails := k.CustomerDetails(email)
	if errDetails != nil {
		return errDetails
	}

	if firstName != nil || lastName != nil {
		reconstructedCustomer.FirstName = *firstName
	}

	if lastName != nil {
		reconstructedCustomer.LastName = *lastName

		haveUpdates = true
	}

	return k.storeCustomer(reconstructedCustomer)
}

func (k *AuthKV) UpdatePassword(email, newPassword string) error {
	reconstructedCustomer, errDetails := k.CustomerDetails(email)
	if errDetails != nil {
		return errDetails
	}

	hash, errHash := auth.HASHPassword(newPassword, reconstructedCustomer.PasswordSalt, 14)
	if errHash != nil {
		return errHash
	}

	reconstructedCustomer.PasswordHash = string(hash)

	return k.storeCustomer(reconstructedCustomer)
}

func (k *AuthKV) Authenticate(email, password string) error {
	reconstructedCustomer, errDetails := k.CustomerDetails(email)
	if errDetails != nil {
		return auth.ErrInternal
	}

	if !auth.CheckPasswordHash(password, reconstructedCustomer.PasswordSalt, reconstructedCustomer.PasswordHash) {
		return auth.ErrUnknownCredentials
	}

	return nil
}

// LostPasswordRequest Method checks if valid email. If yes returns temporary password.
func (k *AuthKV) LostPasswordRequest(email string) (string, error) {
	if _, errDetails := k.CustomerDetails(email); errDetails != nil {
		return "", errDetails
	}

	generatedPass := auth.RandomString(10)

	if errUpd := k.UpdatePassword(email, generatedPass); errUpd != nil {
		return "", errUpd
	}

	return generatedPass, nil
}

func (k *AuthKV) DeleteCustomer(email string) error {
	if _, errDetails := k.CustomerDetails(email); errDetails != nil {
		return errDetails
	}

	return k.Store.DeleteKVByK([]byte(email))
}

func (k *AuthKV) CustomerDetails(email string) (*auth.Customer, error) {
	cust, errGet := k.Store.GetVByK([]byte(email))
	if errGet != nil {
		return nil, KVStoreError{
			Issue: errGet,
		}
	}

	var c auth.Customer

	if errDecode := auth.Decoder(cust, &c); errDecode != nil {
		return nil, TransformationError{
			Issue: errDecode,
		}
	}

	if &c == nil {
		return nil, ItemNotFoundError{
			Issue: fmt.Errorf("customer with email:%s was not found", email),
		}
	}

	return &c, nil
}
