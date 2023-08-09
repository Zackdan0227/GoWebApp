package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Zackdan0227/gowebapp/database"
	"github.com/Zackdan0227/gowebapp/models"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type apiConfig struct {
	fileserverHits int
	DB             *database.DB
	jwtSecret      string
}

type profaneDictionary struct {
	Replacement map[string]string
}

const cost = 12

func main() {

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	const port = "8080"
	const filepathRoot = "."
	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatal(err)
	}

	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if dbg != nil && *dbg {
		err := db.ResetDB()
		if err != nil {
			log.Fatal(err)
		}
	}

	r := chi.NewRouter()

	apiCfg := apiConfig{
		fileserverHits: 0,
		DB:             db,
		jwtSecret:      jwtSecret,
	}

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot))))
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)

	logoHandler := http.FileServer(http.Dir(filepathRoot))
	r.Handle("/assets/logo.png", logoHandler)

	apiRouter := chi.NewRouter()

	apiRouter.Get("/healthz", handlerReadiness)
	apiRouter.Post("/chirps", apiCfg.handlerPostChirp)
	apiRouter.Get("/chirps", apiCfg.handlerGetChirps)
	apiRouter.Get("/chirps/{chirpID}", apiCfg.handlerGetChirpByID)
	apiRouter.Post("/users", apiCfg.handlerPostUser)
	apiRouter.Post("/login", apiCfg.handlerUserLogin)
	apiRouter.Put("/users", apiCfg.handlerUpdateUser)
	apiRouter.Post("/refresh", apiCfg.handlerRefreshToken)
	apiRouter.Post("/revoke", apiCfg.handlerRevoke)
	adminRouter := chi.NewRouter()
	adminRouter.Get("/metrics", apiCfg.handlerMetrics)

	r.Mount("/api", apiRouter)
	r.Mount("/admin", adminRouter)

	corsMux := middlewareCors(r)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}

	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})

}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	htmlContent := fmt.Sprintf(`
	<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
	
	</html>`, cfg.fileserverHits)

	fmt.Fprintln(w, htmlContent)
}

func (cfg *apiConfig) handlerPostChirp(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong when decoding the json data")
		return
	}

	clean, err := validateChirp(params.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	chirp, err := cfg.DB.CreateChirp(clean)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create chirp to DB")
		return
	}

	respondWithJSON(w, http.StatusCreated, models.Chirp{
		Id:   chirp.Id,
		Body: chirp.Body,
	})

}

func (cfg *apiConfig) handlerPostUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Error decoding JSON: %v", err))
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), cost)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong when hashing user password")
		return
	}

	user, err := cfg.DB.CreateUser(params.Email, hashedPassword)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create new user to DB")
		return
	}

	response := struct {
		ID    int    `json:"id"`
		Email string `json:"email"`
	}{
		ID:    user.ID,
		Email: user.Email,
	}
	respondWithJSON(w, http.StatusCreated, response)

}

func (cfg *apiConfig) handlerUserLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong when decoding the json data")
		return
	}

	//get user by email from backend
	user, err := cfg.DB.GetUserByEmail(params.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if bcrypt.CompareHashAndPassword(user.Password, []byte(params.Password)) != nil {
		respondWithError(w, http.StatusUnauthorized, "password does not match")
		return
	}

	currentTime := time.Now().UTC()
	//create jwt
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   fmt.Sprint(user.ID),
	})
	accessTokenString, err := accessToken.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy-refresh",
		IssuedAt:  jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 60)),
		Subject:   fmt.Sprint(user.ID),
	})
	refreshTokenString, err := refreshToken.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := struct {
		ID            int    `json:"id"`
		Email         string `json:"email"`
		Token         string `json:"token"`
		Refresh_token string `json:"refresh_token"`
	}{
		ID:            user.ID,
		Email:         user.Email,
		Token:         accessTokenString,
		Refresh_token: refreshTokenString,
	}
	respondWithJSON(w, http.StatusOK, response)
}

type Claims struct {
	jwt.RegisteredClaims
}

func validateJWT(jwtSecret []byte, r *http.Request) (string, error) {
	requestToken := r.Header.Get("Authorization")

	tokenString := strings.TrimPrefix(requestToken, "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return "", err
	}
	if !token.Valid {
		err := errors.New("token is invalid")
		return "", err
	}

	if claims.Issuer == "chirpy-refresh" {
		err := errors.New("refresh is not allowed")
		return "", err
	}
	currentTime := time.Now().UTC()
	if claims.ExpiresAt != nil && currentTime.After(claims.ExpiresAt.Time) {
		err := errors.New("token has expired")
		return "", err
	}
	return claims.Subject, nil
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {

	userID, err := validateJWT([]byte(cfg.jwtSecret), r)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong when decoding the json data")
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), cost)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong when hashing user password")
		return
	}
	// Use the userID to update the user in the database
	updatedUser, err := cfg.DB.UpdateUser(userID, params.Email, hashedPassword)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not update user password/email")
		return
	}

	response := struct {
		ID    int    `json:"id"`
		Email string `json:"email"`
	}{
		ID:    updatedUser.ID,
		Email: updatedUser.Email,
	}
	respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) handlerRefreshToken(w http.ResponseWriter, r *http.Request) {
	requestToken := r.Header.Get("Authorization")

	tokenString := strings.TrimPrefix(requestToken, "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.jwtSecret), nil
	})

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !token.Valid {
		respondWithError(w, http.StatusUnauthorized, "token is invalid")
		return
	}

	if claims.Issuer != "chirpy-refresh" {
		respondWithError(w, http.StatusUnauthorized, "not a refresh token")
		fmt.Println(claims.Issuer)
		return
	}

	isRevoked, err := cfg.DB.IsTokenRevoked(tokenString)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't check session")
		return
	}
	if isRevoked {
		respondWithError(w, http.StatusUnauthorized, "Refresh token is revoked")
		return
	}
	userID := claims.Subject
	currentTime := time.Now().UTC()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   userID,
	})
	accessTokenString, err := accessToken.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := struct {
		Token string `json:"token"`
	}{
		Token: accessTokenString,
	}
	respondWithJSON(w, http.StatusOK, response)
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("not auth header included in request")
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "Bearer" {
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't find JWT")
		return
	}

	err = cfg.DB.RevokeToken(refreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't revoke session")
		return
	}

	respondWithJSON(w, http.StatusOK, struct{}{})
}

func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := cfg.DB.GetChirps()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve chirps")
		return
	}
	chirps := []models.Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, models.Chirp{
			Id:   dbChirp.Id,
			Body: dbChirp.Body,
		})
	}

	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].Id < chirps[j].Id
	})

	respondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) handlerGetChirpByID(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := cfg.DB.GetChirps()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve chirps")
		return
	}
	idString := chi.URLParam(r, "chirpID")
	id, err := strconv.Atoi(idString)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not convert chirpID from string to int")
		return
	}
	for _, dbChirp := range dbChirps {
		if dbChirp.Id == id {
			chirp := models.Chirp{
				Id:   dbChirp.Id,
				Body: dbChirp.Body,
			}
			respondWithJSON(w, http.StatusOK, chirp)
			return
		}
	}
	respondWithError(w, http.StatusNotFound, fmt.Sprintf("chirpID %d not found in db", id))
}

func validateChirp(body string) (string, error) {
	const chirpMaxLength = 140
	if len(body) > chirpMaxLength {
		return "", errors.New("chirp is too long")
	}

	unclean := strings.ToLower(body)
	profaneDict := NewProfaneDictionary()

	clean := replaceProfaneWithAsterisks(profaneDict, unclean)

	return clean, nil
}

func replaceProfaneWithAsterisks(dict *profaneDictionary, message string) string {
	for word, replacement := range dict.Replacement {
		message = strings.ReplaceAll(message, word, replacement)
	}
	return message
}

func NewProfaneDictionary() *profaneDictionary {
	return &profaneDictionary{
		Replacement: map[string]string{
			"kerfuffle": "****",
			"sharbert":  "****",
			"fornax":    "****",
		},
	}
}

func respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(code)
	w.Write(dat)
}
