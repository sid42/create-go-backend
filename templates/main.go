package main

import (
	"net/http"
	"log"
	"fmt"
	"os"
	"context"

	"github.com/go-pg/pg/v10"
	"github.com/gorilla/mux"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func main () { 
	log.Print("attempting to start image server...")

	// db initialization    
	db_user := os.Getenv("DB_USER")
	db_name := os.Getenv("DB_NAME")
	db_port := os.Getenv("DB_PORT")
	db_host := os.Getenv("DB_HOST")
	db_password := os.Getenv("DB_PASSWORD")

	opt, err := pg.ParseURL(fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", db_user, db_password, db_host, db_port, db_name))
	if err != nil {
		log.Fatalf("failed to create db connection url %s", err)
	}

	server.db = pg.Connect(opt)

	if err := server.db.Ping(context.Background()); err != nil {
		log.Fatalf("failed to connect to db %s", err)
	} else {
		log.Print("db connection established")
	}
	
	// routes
	server.r = mux.NewRouter()

	server.r.HandleFunc("/login", server.Login).Methods("POST")
	server.r.HandleFunc("/signup", server.Signup).Methods("POST")
	server.r.HandleFunc("/images", server.AddImages).Methods("PUT")
	server.r.HandleFunc("/images", server.DeleteImages).Methods("DELETE")
	server.r.HandleFunc("/image/{id}", server.FetchImage).Methods("GET")
	server.r.HandleFunc("/search", server.SearchImages).Methods("GET")
	server.r.Use(server.AuthMiddleware)

	log.Print("listening on port 8000")
	log.Fatal(http.ListenAndServe(":8000", server.r))
}