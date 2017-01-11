package driver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/mklimuk/auth/api"
)

//Generator is a generator test driver
type Generator interface {
	CheckHealth() (bool, error)
	GetAll() (*api.Catalog, error)
	DeleteAll() error
	AddRandom() error
	AddTemplate(group, categories, lang, title, desc, text string) error
}

type gen struct {
	baseURL string
}

//New is a generator's constructor
func New(baseURL string) Generator {
	g := gen{baseURL}
	return Generator(&g)
}

func (g *gen) CheckHealth() (bool, error) {
	res, err := http.Get(fmt.Sprintf("%s%s", g.baseURL, "/health"))
	return (res != nil && res.StatusCode == http.StatusOK), err
}

func (g *gen) GetAll() (*api.Catalog, error) {
	var res *http.Response
	var err error
	if res, err = http.Get(fmt.Sprintf("%s%s", g.baseURL, "/catalog")); err != nil {
		return nil, err
	}
	var b []byte
	if b, err = ioutil.ReadAll(res.Body); err != nil {
		return nil, err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(bytes.NewReader(b))
	cat := new(api.Catalog)
	if err = dec.Decode(&cat); err != nil {
		return nil, err
	}
	return cat, err
}

func (g *gen) AddRandom() error {
	return g.add()
}

func (g *gen) AddTemplate(group, categories, lang, title, desc, text string) error {
	return g.add()
}

func (g *gen) add() error {
	var payload []byte
	var err error
	if payload, err = json.Marshal(); err != nil {
		return err
	}
	var res *http.Response
	if res, err = http.Post(fmt.Sprintf("%s%s", g.baseURL, "/catalog"), "application/x.husar.gen.template+json", bytes.NewReader(payload)); err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected response status code: %d", res.StatusCode)
	}
	return nil
}

func (g *gen) DeleteAll() error {
	req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s%s", g.baseURL, "/catalog"), nil)
	var res *http.Response
	var err error
	if res, err = http.DefaultClient.Do(req); err != nil {
		return err
	}
	if res == nil || res.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected response status code: %d", res.StatusCode)
	}
	return nil
}
