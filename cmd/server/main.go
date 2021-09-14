package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

const (
	CookieRedirectURL = "redirect_url"
	CookieState       = "state"
)

//nolint:gochecknoglobals
var (
	Host         = os.Getenv("HOST")
	ClientID     = os.Getenv("CLIENT_ID")
	ClientSecret = os.Getenv("CLIENT_SECRET")
	RedirectURL  = os.Getenv("REDIRECT_URL")
)

//nolint:gochecknoglobals
var (
	signInCompletedTemplate = template.Must(template.ParseFiles("static/html/sign-in-completed.html"))
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

func buildOAuthConfig() oauth2.Config {
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

	return config
}

func auth(w http.ResponseWriter, r *http.Request) {
	config := buildOAuthConfig()

	appURI := r.URL.Query().Get("redirect_url")

	http.SetCookie(w, &http.Cookie{ //nolint:exhaustivestruct
		Name:     CookieRedirectURL,
		Value:    appURI,
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	state := uuid.New().String()

	http.SetCookie(w, &http.Cookie{ //nolint:exhaustivestruct
		Name:     CookieState,
		Value:    state,
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURL := config.AuthCodeURL(state)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func callback(w http.ResponseWriter, r *http.Request) {
	config := buildOAuthConfig()

	ok := verifyState(w, r)
	if !ok {
		return
	}

	token, ok := obtainTokens(w, r, config)
	if !ok {
		return
	}

	parsedURL, ok := createEditorRedirectURL(w, r, token)
	if !ok {
		return
	}

	b, ok := prepareCompletionPage(w, parsedURL)
	if !ok {
		return
	}

	if _, err := w.Write(b); err != nil {
		log.Printf("error writing confirmation page to response: %v", err)

		return
	}
}

func prepareCompletionPage(w http.ResponseWriter, parsedURL *url.URL) ([]byte, bool) {
	var b bytes.Buffer

	err := signInCompletedTemplate.Execute(&b, struct {
		RedirectURL template.URL
	}{
		RedirectURL: template.URL(parsedURL.String()), //nolint:gosec
	})
	if err != nil {
		log.Printf("error preparing completion page with editor redirect url: %v", err)
		http.Error(w, "error preparing completion page with editor redirect url", http.StatusInternalServerError)

		return nil, false
	}

	return b.Bytes(), true
}

func obtainTokens(w http.ResponseWriter, r *http.Request, config oauth2.Config) (*oauth2.Token, bool) {
	code := r.URL.Query().Get("code")

	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("error exchanging code for tokens: %v", err)
		http.Error(w, "error exchanging code for tokens", http.StatusInternalServerError)

		return nil, false
	}

	return token, true
}

func createEditorRedirectURL(w http.ResponseWriter, r *http.Request, token *oauth2.Token) (*url.URL, bool) {
	redirectURL, err := r.Cookie(CookieRedirectURL)
	if err != nil {
		log.Printf("error extracting cookie for redirect url: %v", err)
		http.Error(w, "error extracting cookie for redirect url", http.StatusBadRequest)

		return nil, false
	}

	parsedURL, err := url.Parse(redirectURL.Value)
	if err != nil {
		log.Printf("error redirecting to app url: %v", err)
		http.Error(w, "error redirecting to app url", http.StatusInternalServerError)

		return nil, false
	}

	query := make(url.Values)
	query.Add("access_token", token.AccessToken)
	query.Add("refresh_token", token.RefreshToken)
	query.Add("expiry", token.Expiry.Format(time.RFC3339))
	query.Add("token_type", token.Type())

	parsedURL.RawQuery = query.Encode()

	return parsedURL, true
}

func verifyState(w http.ResponseWriter, r *http.Request) bool {
	actualState := r.URL.Query().Get("state")

	expectedState, err := r.Cookie(CookieState)
	if err != nil {
		log.Printf("error extracting cookie for state: %v", err)
		http.Error(w, "error extracting cookie for state", http.StatusBadRequest)

		return false
	}

	if actualState != expectedState.Value {
		log.Printf("auth failed: invalid state value")
		http.Error(w, "auth failed: invalid state value", http.StatusBadRequest)

		return false
	}

	return true
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.RequestURI, r.Proto)

		h.ServeHTTP(rw, r)
	})
}
