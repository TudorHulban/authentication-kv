package authenticationkv

import (
	"testing"
	"time"

	auth "github.com/TudorHulban/authentication"
	"github.com/stretchr/testify/require"
)

const passwordRaw = "xxx"

func TestAll(t *testing.T) {
	cfg, errCfg := ConfigBadger()
	require.Nil(t, errCfg, "creation of badger store")

	au, errAuth := NewKVAuth(cfg)
	require.Nil(t, errAuth, "creation of authorization object")

	cust := auth.Customer{
		EMail:        "john@smith.com",
		CreatedUNIX:  time.Now().Unix(),
		FirstName:    "John",
		LastName:     "Smith",
		PasswordHash: passwordRaw,
		Role:         "admin",
	}

	require.NoError(t, au.Create(&cust), "creating customer")

	c1, errDet1 := au.CustomerDetails(cust.EMail)
	require.Nil(t, errDet1, "fetching details")

	cust.PasswordHash = c1.PasswordHash
	cust.PasswordSalt = c1.PasswordSalt

	require.Equal(t, cust, *c1)

	require.Equal(t, auth.ErrEmailExists, au.Create(&cust), "customer email already exists")

	first := "Johnathan"
	last := "Roy"

	au.UpdateName(cust.EMail, &first, &last)

	c2, errDet2 := au.CustomerDetails(cust.EMail)
	require.Nil(t, errDet2, "fetching details")
	require.Equal(t, first, c2.FirstName)

	require.NoError(t, au.Authenticate(cust.EMail, passwordRaw), "succesfull authentication")

	newPass := "yyy"

	require.Nil(t, au.UpdatePassword(cust.EMail, newPass))
	require.Equal(t, au.Authenticate(cust.EMail, passwordRaw), auth.ErrUnknownCredentials)
	require.Nil(t, au.Authenticate(cust.EMail, newPass))

	genPass, errPass := au.LostPasswordRequest(cust.EMail)
	require.Nil(t, errPass)
	require.Nil(t, au.Authenticate(cust.EMail, genPass))

	require.Nil(t, au.DeleteCustomer(cust.EMail))
}
