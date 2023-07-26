package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

type apiConfig struct {
	fileserverHits int
}

type profaneDictionary struct {
	Replacement map[string]string
}

func main() {
	const port = "8080"
	const filepathRoot = "."

	r := chi.NewRouter()

	apiCfg := apiConfig{
		fileserverHits: 0,
	}

	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot))))
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)

	logoHandler := http.FileServer(http.Dir(filepathRoot))
	r.Handle("/assets/logo.png", logoHandler)

	apiRouter := chi.NewRouter()

	apiRouter.Get("/healthz", handlerReadiness)
	apiRouter.Post("/validate_chirp", handlerValidateChirp)

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

func handlerValidateChirp(w http.ResponseWriter, r *http.Request) {
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

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	unclean := strings.ToLower(params.Body)
	profaneDict := NewProfaneDictionary()

	clean := replaceProfaneWithAsterisks(profaneDict, unclean)

	respondWithJson(w, http.StatusOK, clean)

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

func respondWithJson(w http.ResponseWriter, statusCode int, payload string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"cleaned_body": payload}
	json.NewEncoder(w).Encode(response)
}
