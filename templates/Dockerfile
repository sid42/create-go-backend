FROM golang:latest

RUN mkdir /app
WORKDIR /app/backend

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .