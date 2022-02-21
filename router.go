package idp

import (
	"log"
	"net/http"
)

type OauthService interface {
	Authorizer
	TokenGetter
	UserAccesser
	ClientMaker
}

type LoginService interface {
	Authenticator
}

// closure to serve embed template page
func serveTemplateFunc(idpName string) func(tmplName string) http.HandlerFunc {
	return func(tmplName string) http.HandlerFunc {
		t, ok := templates[tmplName]
		if !ok {
			log.Fatal("template missing")
		}
		return func(w http.ResponseWriter, r *http.Request) {
			err := t.Execute(w, struct {
				IDP string
			}{
				IDP: idpName,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			return
		}
		next(w, r)
	}
}

func StartServer(idpName, addr string, oauth OauthService, login LoginService) error {
	serveTemplate := serveTemplateFunc(idpName)

	mux := http.NewServeMux()
	mux.HandleFunc("/sign-in", serveTemplate("sign-in.html"))
	mux.HandleFunc("/sign-up", serveTemplate("sign-up.html"))
	mux.HandleFunc("/client", serveTemplate("client.html"))
	mux.HandleFunc("/api/sign-in", HandleSignIn(idpName, login))
	mux.HandleFunc("/api/sign-up", HandleSignUp(idpName, login))
	mux.HandleFunc("/api/clients", HandlePostClient(oauth))
	mux.HandleFunc("/token", cors(HandleGetToken(oauth)))
	mux.HandleFunc("/user", cors(HandleGetUser(oauth)))
	mux.HandleFunc("/auth", HandleAuth(idpName, oauth))
	mux.HandleFunc("/", serveTemplate("404.html"))
	return http.ListenAndServe(addr, mux)
}
