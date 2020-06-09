package processes

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProcesses(t *testing.T) {
	p := new(Processes)
	var input interface{}
	e := json.Unmarshal([]byte(`{"processes":{"measurement": [
						"blocked",
						"running"]}}`), &input)
	if e == nil {
		_, actual := p.ApplyRule(input)
		expected := []interface{}{map[string]interface{}{
			"fieldpass": []string{"blocked", "running"},
		}}
		assert.Equal(t, expected, actual, "Expected to be equal")
	}
}
