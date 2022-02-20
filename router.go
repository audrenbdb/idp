package idp

import (
	"fmt"
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

func serveTemplate(name string) http.HandlerFunc {
	t, ok := templates[name]
	if !ok {
		log.Fatal("template missing")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		err := t.Execute(w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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

func StartServer(port int, oauth OauthService, login LoginService) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", serveTemplate("login.html"))
	mux.HandleFunc("/client", serveTemplate("client.html"))
	mux.HandleFunc("/api/login", HandleLogin(login))
	mux.HandleFunc("/api/clients", HandlePostClient(oauth))
	mux.HandleFunc("/token", cors(HandleGetAccessToken(oauth)))
	mux.HandleFunc("/user", cors(HandleGetUser(oauth)))
	mux.HandleFunc("/auth", HandleAuth(oauth))
	return http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}
