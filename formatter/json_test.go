package formatter

import "testing"

func TestJSON(t *testing.T) {
	testFormatter(t, JSON, "./testdata/json.json")
}
