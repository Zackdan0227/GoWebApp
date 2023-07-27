package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Zackdan0227/gowebapp/database"
	"github.com/Zackdan0227/gowebapp/models"
	"github.com/go-chi/chi/v5"
)

type apiConfig struct {
	fileserverHits int
	DB             *database.DB
}

type profaneDictionary struct {
	Replacement map[string]string
}

func main() {
	const port = "8080"
	const filepathRoot = "."
	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()

	apiCfg := apiConfig{
		fileserverHits: 0,
		DB:             db,
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
	}

	respondChirpWithJson(w, http.StatusCreated, models.Chirp{
		Id:   chirp.Id,
		Body: chirp.Body,
	})

}

func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {

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

// func respondWithValid(w http.ResponseWriter, statusCode int, b bool) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(statusCode)
// 	response := map[string]bool{"valid": b}
// 	json.NewEncoder(w).Encode(response)
// }

func respondChirpWithJson(w http.ResponseWriter, statusCode int, chirp models.Chirp) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := models.Chirp{
		Id:   chirp.Id,
		Body: chirp.Body,
	}
	json.NewEncoder(w).Encode(response)
}
