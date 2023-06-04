package main

import (
	"io"
	"fmt"
	"log"
	"strings"
	"errors"
	"net/http"
	"encoding/json"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/go-pg/pg/v10"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/dchest/uniuri"
	"github.com/gorilla/mux"
)

const (
	signing_key = "very_secure_jwt_passphrase"
)

func generateTokenString(user User) string {
	//new token object with user data
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Email" : user.Email,
	})
	
	//signing the token to get token string to be sent to user 
	encoded_token, err := token.SignedString([]byte(signing_key))
	if err != nil {
		log.Fatalf("error while generating token %s", err)
	}

	return encoded_token
}

func getTokenFomHeader(r http.Request) (string, error) {
	header := r.Header.Get("x-authentication-token")
	
	if len(header) == 0{
		//no auth token provided
		return "", fmt.Errorf("No auth token provided")
	} else {
		header_split := strings.Split(header, " ")
		if len(header_split) == 1 {
			// either 'bearer' or token provided, invalid usage
			return "", fmt.Errorf("Invalid usage")
		} else if header_split[0] != "Bearer" {
			return "", fmt.Errorf("Invalid usage")
		} else {
			return header_split[1], nil
		}
	}
}

func getTokenClaims(r http.Request) (jwt.Claims, error) {
	var encoded_token string
	var err error
	if encoded_token, err = getTokenFomHeader(r); err != nil {
		return nil, fmt.Errorf("error in auth")
	}

	var token *jwt.Token
	if token, err = jwt.Parse(encoded_token, checkSigningMethod); err != nil {
		return nil, fmt.Errorf("error in auth")
	}

	return token.Claims, nil
}

func checkSigningMethod(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Error occured")
	}
	return []byte(signing_key), nil
}

func (s *Server) Signup(w http.ResponseWriter, r *http.Request) {
	var u User
	_ = json.NewDecoder(r.Body).Decode(&u)
	
	//check if user with provided email already exists
	var res User
	err := s.db.Model(&res).
		Where("email = ?", u.Email).
		Select()

	if errors.Is(err, pg.ErrNoRows) && u.Email != "" {
		_, err = s.db.Model(&u).Insert()
		if err != nil {
			log.Printf("error inserting user in database %s", err)
		}

		log.Print("successfully created user account")
		json.NewEncoder(w).Encode(Token{Token: generateTokenString(u)})
	
	} else {
		log.Printf("error signup up %s %s", err, u.Email)
		http.Error(w, "User with provided e-mail already exists or is invalid", http.StatusConflict)
	}
}

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	var u User
	_ = json.NewDecoder(r.Body).Decode(&u)

	var res User
	err := s.db.Model(&res).
		Where("email = ?", u.Email).
		Where("password = ?", u.Password).
		Select()

	if err != nil || res == (User{}){
		http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
	} else {
		log.Print("successfully logged in")
		json.NewEncoder(w).Encode(Token{Token: generateTokenString(res)})
	}

}

func (s *Server) AddImages(w http.ResponseWriter, r *http.Request) {
	claims, err := getTokenClaims(*r)
	if err != nil {
		http.Error(w, "Auth error", http.StatusInternalServerError)
	}
	email := claims.(jwt.MapClaims)["Email"].(string)

	// parse multiform 
	log.Print("parsing form")
	if err = r.ParseMultipartForm(1 << 15); err != nil {
		http.Error(w, "Error uploading image, request too big", http.StatusBadRequest)
		return
	} 

	if len(r.MultipartForm.File) == 0 || len(r.MultipartForm.File) > 10 {
		http.Error(w, "Invalid number of files to upload, please make sure to add between 1 and 10 files", http.StatusBadRequest)
		return
	}
	
	var keys []string
	for form_key, _ := range r.MultipartForm.File {
		log.Printf("Uploading %s", form_key)

		file, header, err := r.FormFile(form_key)
		if err != nil {
			http.Error(w, "Error uploading image", http.StatusInternalServerError)
			return
		}

		file_type := strings.Split(header.Filename, ".")
		// generate random url for image to allow multiple uploads of same file
		key := fmt.Sprintf("%s.%s", uniuri.New(), file_type[len(file_type) - 1])
		log.Printf("filename: %s size: %d KB", key, header.Size/1024)
		
		// persist image to bucket
		_, err = s.s3_session.PutObject(&s3.PutObjectInput{
			Bucket: aws.String(s.s3_bucket),
			Key:    aws.String(key),
			Body:   file,
		})
		if err != nil {
			http.Error(w, "Error uploading image", http.StatusInternalServerError)
			return
		}
		
		keys = append(keys, key)
		file.Close()
	}

	// insert into database
	var images []Image
	var ids ImageIds
	for _, key := range keys {
		images = append(images, Image{
			Key: key,
			UserEmail: email, 
		})
	}
	_, err = s.db.Model(&images).Returning("id").Insert()
	if err != nil {
		http.Error(w, "Error uploading image", http.StatusInternalServerError)
		return
	}

	// encode and send ids to client
	for _, i := range images {
		ids.Ids = append(ids.Ids, i.Id)
	}

	log.Print("successfully added images")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ids)
}

func (s *Server) DeleteImages(w http.ResponseWriter, r *http.Request) {
	claims, err := getTokenClaims(*r)
	if err != nil {
		http.Error(w, "Auth error", http.StatusInternalServerError)
	}
	email := claims.(jwt.MapClaims)["Email"].(string)

	var ids ImageIds
	if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if len(ids.Ids) == 0 {
		http.Error(w, "No images to delete", http.StatusBadRequest)
		return
	}
	
	// check if deleting another user's images
	var images []Image		
	if err := s.db.Model(&images).Where("id in (?)", pg.In(ids.Ids)).Select(); err != nil {
		http.Error(w, "Error deleting image", http.StatusInternalServerError)
		return
	} 

	for _, i := range images {
		if i.UserEmail != email {
			http.Error(w, "Unable to delete another user's image", http.StatusUnauthorized)
			return
		}
	}
	if len(images) != len(ids.Ids) {
		http.Error(w, "Image does not exist", http.StatusBadRequest)
		return
	}

	// delete from bucket 
	for _, i := range images {
		log.Printf("deleting %s", i.Key)
		_, err = s.s3_session.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(s.s3_bucket),
			Key: aws.String(i.Key),
		})
		if err != nil {
			http.Error(w, "Error deleting image", http.StatusInternalServerError)
			return
		}
	}

	// delete from db 
	_, err = s.db.Model(&images).Where("id in (?)", pg.In(ids.Ids)).Delete()	
	if err != nil {
		http.Error(w, "Error deleting image", http.StatusInternalServerError)
		return
	}

	log.Print("succesfully deleted images")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("Succesfully deleted images")
}

func (s *Server) SearchImages(w http.ResponseWriter, r *http.Request) {
	var filter SearchImageRequest
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if len(filter.ByEmails) == 0 {
		http.Error(w, "No search input", http.StatusBadRequest)
		return
	}

	var ids ImageIds
	var images []Image
	err := s.db.Model(&images).
		Where("user_email in (?)", pg.In(filter.ByEmails)).
		OrderExpr("created_at DESC").
		Select()

	if err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			http.Error(w, "No images found", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error searching for image", http.StatusInternalServerError)
		return
	}
	
	log.Printf("number of images found %d", len(images))
	for _, i := range images {
		ids.Ids = append(ids.Ids, i.Id)
	}
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ids)
}

func (s *Server) FetchImage(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	i := Image{
		Id: id,
	}

	if err := s.db.Model(&i).WherePK().Select(); err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			http.Error(w, "No image found with given id", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error fetching image", http.StatusInternalServerError)
		return
	}

	log.Printf("fetching %s", i.Key)
	resp, err := s.s3_session.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s.s3_bucket),
		Key: aws.String(i.Key),
	})
	if err != nil {
		http.Error(w, "Error searching for image", http.StatusInternalServerError)
		return
	}

	log.Printf("writing fetched file")
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, "Error searching for image", http.StatusInternalServerError)
		return
	}

	log.Print("succesfully fetched image")
}

func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Print(r.Method, " ", r.RequestURI)

		if r.RequestURI == "/login" || r.RequestURI == "/signup" {
			next.ServeHTTP(w, r)
		} else {
			// authentication to check if user is valid
			encoded_token, err := getTokenFomHeader(*r)

			if err != nil {
				log.Print("error occured in auth middleware ", err)
				http.Error(w, "Forbidden", http.StatusForbidden)
			} else {
				// parse token from jwt encoding
				token, err := jwt.Parse(encoded_token, checkSigningMethod)
			
				if err != nil{	
					log.Print("unauthorized request %s", err)
					http.Error(w, "Forbidden", http.StatusForbidden)
				
				} else if !token.Valid {	
					log.Print("invalid jwt token")
					http.Error(w, "Forbidden", http.StatusForbidden)
					
				} else if token.Valid {
					next.ServeHTTP(w, r)
				}
			}
		}
    })
}