package main

import "testing"

func TestSignVerify(t *testing.T) {
	src := "hi"
	node := "N0"

	sig := Sign(src, node)
	if err := Verify(src, sig, node); err != nil {
		t.Fatal(err)
	}
}
