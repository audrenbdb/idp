package idp

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
)

const (
	layoutsDir   = "templates/layouts"
	templatesDir = "templates"
	extension    = "/*.html"
)

var (
	//go:embed templates/* templates/layouts/*
	files     embed.FS
	templates map[string]*template.Template
)

// init initializes :
//
// - embed templates
func init() {
	if templates == nil {
		templates = make(map[string]*template.Template)
	}
	tmplFiles, err := fs.ReadDir(files, templatesDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, tmpl := range tmplFiles {
		if tmpl.IsDir() {
			continue
		}

		pt, err := template.ParseFS(files, templatesDir+"/"+tmpl.Name(), layoutsDir+extension)
		if err != nil {
			log.Fatal(err)
		}

		templates[tmpl.Name()] = pt
	}
}
