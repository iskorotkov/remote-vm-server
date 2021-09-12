package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

//nolint:gochecknoglobals
var (
	Host         = os.Getenv("HOST")
	ClientID     = os.Getenv("CLIENT_ID")
	ClientSecret = os.Getenv("CLIENT_SECRET")
	RedirectURL  = os.Getenv("REDIRECT_URL")
)

func main() {
	startHTTPServer()
}

func startHTTPServer() {
	r := mux.NewRouter()
	r.Use(logRequests)
	r.HandleFunc("/api/v1/auth", auth).Methods("POST")
	r.HandleFunc("/api/v1/callback", callback).Methods("POST")

	log.Println("service started listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func auth(w http.ResponseWriter, r *http.Request) {
	config := oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   fmt.Sprintf("%s/v1/oauth/authorize", Host),
			TokenURL:  fmt.Sprintf("%s/v1/oauth/token", Host),
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: RedirectURL,
		Scopes:      []string{"read", "write"},
	}

	// TODO: Generate and store state.
	url := config.AuthCodeURL("state")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callback(w http.ResponseWriter, r *http.Request) {
	config := oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   fmt.Sprintf("%s/v1/oauth/authorize", Host),
			TokenURL:  fmt.Sprintf("%s/v1/oauth/token", Host),
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: RedirectURL,
		Scopes:      []string{"read", "write"},
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, "error reading request body", http.StatusBadRequest)

		return
	}

	var body struct {
		Code string `json:"code"`
	}

	err = json.Unmarshal(b, &body)
	if err != nil {
		log.Printf("error parsing request body: %v", err)
		http.Error(w, "error parsing request body", http.StatusBadRequest)

		return
	}

	token, err := config.Exchange(context.Background(), body.Code)
	if err != nil {
		log.Printf("error exchanging code for tokens: %v", err)
		http.Error(w, "error exchanging code for tokens", http.StatusInternalServerError)

		return
	}

	b, err = json.Marshal(token)
	if err != nil {
		log.Printf("error serializing token: %v", err)
		http.Error(w, "error serializing token", http.StatusInternalServerError)

		return
	}

	_, _ = fmt.Fprint(w, b)
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.RequestURI, r.Proto)

		h.ServeHTTP(rw, r)
	})
}
