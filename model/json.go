package model

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/adrienkohlbecker/errors"
)

type JSON struct {
	KMSKeyArn   string             `json:"kms_key_arn"`
	Context     map[string]*string `json:"context"`
	Credentials []Credential       `json:"credentials"`
}

type Credential struct {
	Name        string     `json:"name"`
	Description string     `json:"desctiption"`
	AddedAt     time.Time  `json:"added_at"`
	RotatedAt   *time.Time `json:"rotated_at"`
	Value       string     `json:"value"`
}

func Import(path string) (*JSON, errors.Error) {

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.WrapPrefix(err, fmt.Sprintf("Unable to read file at %s", path), 0)
	}

	j := &JSON{}
	err = json.Unmarshal(bytes, j)
	if err != nil {
		return nil, errors.WrapPrefix(err, fmt.Sprintf("Unable to decode JSON at %s", path), 0)
	}

	return j, nil

}

func (j *JSON) NameExists(name string) bool {

	for _, item := range j.Credentials {
		if item.Name == name {
			return true
		}
	}

	return false

}

func (j *JSON) Export(path string) errors.Error {

	bytes, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return errors.WrapPrefix(err, "Unable to marshall JSON", 0)
	}

	bytes = append(bytes, []byte("\n")...)

	err = ioutil.WriteFile(path, bytes, 0700)
	if err != nil {
		return errors.WrapPrefix(err, fmt.Sprintf("Unable to write file at path %s", path), 0)
	}

	return nil

}
