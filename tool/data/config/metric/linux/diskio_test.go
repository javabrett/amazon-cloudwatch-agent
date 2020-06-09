package linux

import (
	"testing"

	"github.com/aws/amazon-cloudwatch-agent/tool/runtime"

	"github.com/stretchr/testify/assert"
)

func TestDiskIO_ToMap(t *testing.T) {
	expectedKey := "diskio"
	expectedValue := map[string]interface{}{"resources": []string{"*"}, "measurement": []string{"io_time", "write_bytes", "read_bytes", "writes", "reads"}}
	ctx := &runtime.Context{}
	conf := new(DiskIO)
	conf.Enable()
	key, value := conf.ToMap(ctx)
	assert.Equal(t, expectedKey, key)
	assert.Equal(t, expectedValue, value)
}
