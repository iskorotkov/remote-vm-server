package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

//nolint:gochecknoglobals
var (
	Host         = os.Getenv("HOST")
	ClientID     = os.Getenv("CLIENT_ID")
	ClientSecret = os.Getenv("CLIENT_SECRET")
	RedirectURL  = os.Getenv("REDIRECT_URL")
	AppURL       = os.Getenv("APP_URL")
)

func main() {
	startHTTPServer()
}

func startHTTPServer() {
	r := mux.NewRouter()
	r.Use(logRequests)
	r.HandleFunc("/api/v1/auth", auth).Methods("GET")
	r.HandleFunc("/api/v1/callback", callback).Methods("GET")

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
	redirectURL := config.AuthCodeURL("state")
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
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

	// state := r.URL.Query().Get("state")

	code := r.URL.Query().Get("code")

	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("error exchanging code for tokens: %v", err)
		http.Error(w, "error exchanging code for tokens", http.StatusInternalServerError)

		return
	}

	redirectURL, err := url.Parse(AppURL)
	if err != nil {
		log.Printf("error redirecting to app url: %v", err)
		http.Error(w, "error redirecting to app url", http.StatusInternalServerError)

		return
	}

	query := make(url.Values)
	query.Add("access_token", token.AccessToken)
	query.Add("refresh_token", token.RefreshToken)
	query.Add("expiry", token.Expiry.Format(time.RFC3339))
	query.Add("token_type", token.Type())

	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.RequestURI, r.Proto)

		h.ServeHTTP(rw, r)
	})
}
