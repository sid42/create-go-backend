package main

import (
	"time"
	"github.com/go-pg/pg/v10"
	"github.com/gorilla/mux"
)

type Server struct {
	r				*mux.Router
	db				*pg.DB
	s3_session		*s3.S3
	s3_bucket		string
}

type User struct {
	tableName	struct{} `pg:"users"`

	Id			string `json:"-" pg:",pk" `
	Email		string `json:"email"`	
	Password	string `json:"password"`
}

type Token struct {
	Token	string `json:"token"`
}