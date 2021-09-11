package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	r.Use(logRequests)

	r.HandleFunc("/api/v1/do/signup", signup).Methods("POST")
	r.HandleFunc("/api/v1/do/callback", callback).Methods("POST")

	log.Println("service started listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func signup(w http.ResponseWriter, r *http.Request) {

}

func callback(w http.ResponseWriter, r *http.Request) {

}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.RequestURI, r.Proto)

		h.ServeHTTP(rw, r)
	})
}
