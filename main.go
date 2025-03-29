package main

import (
	"chirpy_bootdev/internal/auth"
	"chirpy_bootdev/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	tokenSecret    string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})

}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	hits := cfg.fileserverHits.Load()
	// w.Write([]byte(fmt.Sprintf("Hits: %d", hits)))
	w.Write([]byte(fmt.Sprintf(`
	<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
	</html>`, hits)))

}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {

	if cfg.platform != "dev" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	err := cfg.db.DeleteAllUsers(r.Context())
	if err != nil {
		http.Error(w, "failed to delete users", http.StatusInternalServerError)
		return
	}

	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

func customHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) postChirp(w http.ResponseWriter, r *http.Request) {

	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, `{"error": "missing or invalid token"}`, http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.tokenSecret)
	if err != nil {
		http.Error(w, `{"error": "invalid or expired token"}`, http.StatusUnauthorized)
		return
	}

	type parameters struct {
		Body string `json:"body"`
		//User_id uuid.UUID `json:"user_id"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	if len(params.Body) > 140 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf(`{
		"error": "Chirp is too long"
		}`)))
		return
	}

	replacements := map[string]string{
		"kerfuffle":      "****",
		"sharbert":       "****",
		"fornax":         "****",
		"Kerfuffle":      "****",
		"Fornsharbertax": "****",
		"Fornax":         "****",
	}
	result := params.Body
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	chirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   result,
		UserID: userID,
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		return
	}

	type returnVals struct {
		// the key will be the name of struct field unless you give it an explicit JSON tag
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Body       string    `json:"body"`
		User_id    uuid.UUID `json:"user_id"`
	}

	respBody := returnVals{
		Id:         chirp.ID,
		Created_at: chirp.CreatedAt,
		Updated_at: chirp.UpdatedAt,
		Body:       chirp.Body,
		User_id:    chirp.UserID,
	}
	dat, err := json.Marshal(respBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(dat)

}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.db.GetChirps(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		return
	}

	dat, err := json.Marshal(chirps)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) getChirpByID(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID") // Get path param
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid chirp ID"}`, http.StatusBadRequest)
		return
	}

	chirp, err := cfg.db.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		http.Error(w, `{"error": "Chirp not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(chirp)
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, `{"error": "missing or invalid token"}`, http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.tokenSecret)
	if err != nil {
		http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
		return
	}

	chirpIDStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		http.Error(w, `{"error": "invalid chirp ID"}`, http.StatusBadRequest)
		return
	}

	chirp, err := cfg.db.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		http.Error(w, `{"error": "chirp not found"}`, http.StatusNotFound)
		return
	}

	if chirp.UserID != userID {
		http.Error(w, `{"error": "forbidden"}`, http.StatusForbidden)
		return
	}

	err = cfg.db.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		http.Error(w, `{"error": "could not delete chirp"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent) // 204
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		// an error will be thrown if the JSON is invalid or has the wrong types
		// any missing fields will simply have their values in the struct set to their zero value
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		log.Printf("Error decoding parameters: %s", err)
		return
	}

	type returnVals struct {
		// the key will be the name of struct field unless you give it an explicit JSON tag
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Email      string    `json:"email"`
	}

	passwordHash, err := auth.HashPassword(params.Password)
	if err != nil {
		http.Error(w, `{"error": "failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		HashedPassword: passwordHash,
		Email:          params.Email,
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		return
	}
	respBody := returnVals{
		Id:         user.ID,
		Created_at: user.CreatedAt,
		Updated_at: user.UpdatedAt,
		Email:      user.Email,
	}
	dat, err := json.Marshal(respBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(dat)
}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, `{"error": "missing or invalid token"}`, http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.tokenSecret)
	if err != nil {
		http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
		return
	}

	type updateParams struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var params updateParams
	err = json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, `{"error": "invalid body"}`, http.StatusBadRequest)
		return
	}

	hashed, err := auth.HashPassword(params.Password)
	if err != nil {
		http.Error(w, `{"error": "could not hash password"}`, http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		Email:          params.Email,
		HashedPassword: hashed,
		ID:             userID,
	})
	if err != nil {
		http.Error(w, `{"error": "could not update user"}`, http.StatusInternalServerError)
		return
	}

	type userResponse struct {
		ID        uuid.UUID `json:"id"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	resp := userResponse{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	type credentials struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	var creds credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, `{"error": "Invalid request"}`, http.StatusBadRequest)
		return
	}

	user, err := cfg.db.GetUserByEmail(r.Context(), creds.Email)
	if err != nil {
		http.Error(w, `{"error": "Incorrect email or password"}`, http.StatusUnauthorized)
		return
	}

	if err := auth.CheckPasswordHash(user.HashedPassword, creds.Password); err != nil {
		http.Error(w, `{"error": "Incorrect email or password"}`, http.StatusUnauthorized)
		return
	}
	token, _ := auth.MakeJWT(user.ID, cfg.tokenSecret, time.Hour)

	refreshToken, _ := auth.MakeRefreshToken()
	cfg.db.InsertRefreshToken(r.Context(), database.InsertRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	})

	type returnVals struct {
		// the key will be the name of struct field unless you give it an explicit JSON tag
		Id            uuid.UUID `json:"id"`
		Created_at    time.Time `json:"created_at"`
		Updated_at    time.Time `json:"updated_at"`
		Email         string    `json:"email"`
		Token         string    `json:"token"`
		Refresh_token string    `json:"refresh_token"`
	}

	resp := returnVals{
		Id:            user.ID,
		Created_at:    user.CreatedAt,
		Updated_at:    user.UpdatedAt,
		Email:         user.Email,
		Token:         token,
		Refresh_token: refreshToken,
	}

	dat, err := json.Marshal(resp)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf(`{
			"error": "Something went wrong"
		}`)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	//json.NewEncoder(w).Encode(resp)
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, `{"error": "invalid or missing token"}`, http.StatusUnauthorized)
		return
	}

	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
		return
	}

	newToken, err := auth.MakeJWT(user.ID, cfg.tokenSecret, time.Hour)
	if err != nil {
		http.Error(w, `{"error": "failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": newToken})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, `{"error": "invalid or missing token"}`, http.StatusUnauthorized)
		return
	}

	err = cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		http.Error(w, `{"error": "unable to revoke token"}`, http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	platform := os.Getenv("PLATFORM")
	tokenSecret := os.Getenv("JWT_SECRET")

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}

	defer db.Close()
	dbQueries := database.New(db)

	// apiCfg := apiConfig{
	// 	db: dbQueries,
	// }

	fmt.Println("Database connected and dbQueries ready!")

	//--------------------
	apiCfg := &apiConfig{
		db:          dbQueries,
		platform:    platform,
		tokenSecret: tokenSecret,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUser)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.postChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByID)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)
	mux.HandleFunc("GET /api/healthz", customHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)

	//mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	//mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))

	// ----------------------------
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()
}
