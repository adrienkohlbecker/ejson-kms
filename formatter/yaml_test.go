package formatter

import "testing"

func TestYAML(t *testing.T) {
	testFormatter(t, YAML, "./testdata/yaml.yaml")
}
