package main

import (
	"fmt"
	"net/http"
)

func home_page(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Test")
}

func test(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Test222")
}

func handleRequest() {
	http.HandleFunc("/", home_page)
	http.HandleFunc("/test2", test)
	http.ListenAndServe(":8080", nil)
}

func main() {
	handleRequest()
}
