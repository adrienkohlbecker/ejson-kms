package formatter

import "testing"

func TestDotenv(t *testing.T) {
	testFormatter(t, Dotenv, "./testdata/dotenv")
}
