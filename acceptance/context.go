package acceptance

import (
	"fmt"

	"github.com/DATA-DOG/godog"
	"github.com/mklimuk/auth/acceptance/driver"
	"github.com/mklimuk/auth/api"
)

//Context is a feature execution context
type Context struct {
	gen driver.Generator
	cat *api.Catalog
}

//FeatureContext initializes the context
func FeatureContext(s *godog.Suite, gen driver.Generator) {
	ctx := &Context{gen: gen}
	s.Step(`^brak szablonów$`, ctx.deleteAll)
	s.Step(`^pobiorę katalog$`, ctx.getCatalog)
	s.Step(`^na liście będzie (\d+) szablon(?:ów)?$`, ctx.checkSize)
	s.Step(`że w katalogu znajduje się (\d+) szablon(?:ów)?`, ctx.addRandom)
	s.Step(`^dodam do grupy "([^"]*)", kategorii "([^"]*)", w języku "([^"]*)" szablon o tytule "([^"]*)", opisie "([^"]*)" i treści "([^"]*)"$`, ctx.addTemplate)
	s.Step(`^w grupie "([^"]*)" będzie (\d+) szablon(?:ów)?$`, ctx.checkGroupSize)
	s.Step(`^w kategorii "([^"]*)" będzie (\d+) szablon(?:ów)?$`, ctx.checkCategorySize)

}

func (c *Context) deleteAll() error {
	return c.gen.DeleteAll()
}

func (c *Context) getCatalog() error {
	var err error
	if c.cat, err = c.gen.GetAll(); err != nil {
		return err
	}
	return nil
}

func (c *Context) addTemplate(group, categories, lang, title, desc, text string) error {
	return c.gen.AddTemplate(group, categories, lang, title, desc, text)
}

func (c *Context) addRandom(number int) error {
	var err error
	for i := 0; i < number; i++ {
		if err = c.gen.AddRandom(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Context) checkSize(size int) error {
	if c.cat == nil {
		return fmt.Errorf("Missing catalog content")
	}
	if len(c.cat.Entities) != size {
		return fmt.Errorf("Templates catalog size does not match. Expected: %d, found: %d\n", size, len(c.cat.Entities))
	}
	return nil
}

func (c *Context) checkGroupSize(name string, size int) error {
	if len(c.cat.Groups[name]) != size {
		return fmt.Errorf("Templates group '%s' size does not match. Expected: %d, found: %d\n", name, size, len(c.cat.Entities))
	}
	return nil
}

func (c *Context) checkCategorySize(name string, size int) error {
	if len(c.cat.Categories[name]) != size {
		return fmt.Errorf("Templates category '%s' size does not match. Expected: %d, found: %d\n", name, size, len(c.cat.Entities))
	}
	return nil
}
