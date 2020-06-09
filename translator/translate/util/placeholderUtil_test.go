package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostName(t *testing.T) {
	assert.True(t, getHostName() != unknownHostname)
}

func TestIpAddress(t *testing.T) {
	assert.True(t, getIpAddress() != unknownIpAddress)
}
