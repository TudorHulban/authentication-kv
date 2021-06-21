package authenticationkv

import (
	"testing"
	"time"

	"github.com/TudorHulban/authentication"
	"github.com/stretchr/testify/require"
)

func TestCreate(t *testing.T) {
	cfg, errCfg := ConfigBadger()
	require.Nil(t, errCfg, "creation of badger store")

	au, errAuth := NewKVAuth(cfg)
	require.Nil(t, errAuth, "creation of authorization object")

	cust := auth.Customer{
		EMail:        "john@smith.com",
		CreatedUNIX:  time.Now().Unix(),
		FirstName:    "John",
		LastName:     "Smith",
		PasswordSalt: auth.GenerateSALT(10),
		Password:     "xxx",
		Role:         "admin",
	}

	require.Nil(t, au.Create(cust), "creating customer")

	c, errDet := au.CustomerDetails(cust.EMail)
	require.Nil(t, errDet, "fetching details")

	require.Equal(t, cust, *c)

	require.Equal(t, auth.ErrEmailExists, au.Create(cust), "customer email already exists")
}
