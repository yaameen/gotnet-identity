package main

import (
	"fmt"
	"testing"

	"github.com/yaameen/gotnet-identity/identity"
)

func Test_if_it_generates_correct_password_hash(t *testing.T) {

	password := "welcome123"

	hash := identity.HashPassword(password)

	if len(hash) == 0 {
		t.Error("Could not generate hash")
	}
}

func Test_enerated_pass_correctly_compares(t *testing.T) {

	password := "welcome123"

	hash := identity.HashPassword(password)

	if !identity.VerifyPassword(hash, password) {
		t.Error("Failed to match hashed pass")
	}
}

func Test_Matches_multiple_generated_passwords(t *testing.T) {

	for i := range []int{1, 2, 3, 4, 5, 6, 7} {

		password := "welcome123" + fmt.Sprint(i)

		hash := identity.HashPassword(password)

		if !identity.VerifyPassword(hash, password) {
			t.Error("Failed to match hashed pass")
		}
	}

}
