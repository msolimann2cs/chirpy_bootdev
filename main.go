package main

import (
	// Standard library and third-party imports
	"chirpy_bootdev/internal/auth"
	"chirpy_bootdev/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// Configuration struct for shared dependencies across handlers
type apiConfig struct {
	fileserverHits atomic.Int32 // Tracks visits to the frontend
	db             *database.Queries
	platform       string
	tokenSecret    string
	polkaKey       string
}

// Middleware to increment fileserver hit counter
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// Admin-only endpoint showing number of file server visits
func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	hits := cfg.fileserverHits.Load()
	w.Write([]byte(fmt.Sprintf(`
	<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
	</html>`, hits)))
}

// Admin-only endpoint to reset database and metrics (dev environment only)
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

// Basic health check endpoint
func customHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Endpoint to post a new chirp; JWT authentication required
func (cfg *apiConfig) postChirp(w http.ResponseWriter, r *http.Request) {
	// Extract and validate JWT
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil || tokenString == "" {
		http.Error(w, `{"error": "missing or invalid token"}`, http.StatusUnauthorized)
		return
	}
	userID, err := auth.ValidateJWT(tokenString, cfg.tokenSecret)
	if err != nil {
		http.Error(w, `{"error": "invalid or expired token"}`, http.StatusUnauthorized)
		return
	}

	// Decode request body
	type parameters struct {
		Body string `json:"body"`
	}
	var params parameters
	err = json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, `{"error": "Something went wrong"}`, http.StatusInternalServerError)
		log.Printf("Error decoding parameters: %s", err)
		return
	}
	if len(params.Body) > 140 {
		http.Error(w, `{"error": "Chirp is too long"}`, http.StatusBadRequest)
		return
	}

	// Filter banned words
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

	// Store chirp in DB
	chirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   result,
		UserID: userID,
	})
	if err != nil {
		http.Error(w, `{"error": "Something went wrong"}`, http.StatusInternalServerError)
		return
	}

	// Return created chirp
	type returnVals struct {
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
	dat, _ := json.Marshal(respBody)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(dat)
}

// Get all chirps or filter by author_id, with optional sorting
func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	authorIDStr := r.URL.Query().Get("author_id")
	var chirps []database.Chirp
	var err error

	if authorIDStr != "" {
		authorID, err := uuid.Parse(authorIDStr)
		if err != nil {
			http.Error(w, `{"error": "invalid author_id"}`, http.StatusBadRequest)
			return
		}
		chirps, err = cfg.db.GetChirpsByAuthor(r.Context(), authorID)
	} else {
		chirps, err = cfg.db.GetChirps(r.Context())
	}

	if err != nil {
		http.Error(w, `{"error": "could not retrieve chirps"}`, http.StatusInternalServerError)
		return
	}

	// Optional sorting
	sortParam := r.URL.Query().Get("sort")
	if sortParam == "desc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		})
	} else {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
		})
	}

	dat, _ := json.Marshal(chirps)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

// Retrieve a chirp by ID
func (cfg *apiConfig) getChirpByID(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID")
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
	json.NewEncoder(w).Encode(chirp)
}

// Delete a chirp if the user is the owner
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
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
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
	w.WriteHeader(http.StatusNoContent)
}

// Create a new user with hashed password
func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	var params parameters
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		http.Error(w, `{"error": "Something went wrong"}`, http.StatusInternalServerError)
		log.Printf("Error decoding parameters: %s", err)
		return
	}

	// Hash the password before saving
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
		http.Error(w, `{"error": "Something went wrong"}`, http.StatusInternalServerError)
		return
	}

	// Return created user info
	type returnVals struct {
		Id          uuid.UUID `json:"id"`
		Created_at  time.Time `json:"created_at"`
		Updated_at  time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}
	respBody := returnVals{
		Id:          user.ID,
		Created_at:  user.CreatedAt,
		Updated_at:  user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
	dat, _ := json.Marshal(respBody)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(dat)
}

// Update email and password of a logged-in user
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

	// Hash the new password
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

	// Return updated user info
	type userResponse struct {
		ID          uuid.UUID `json:"id"`
		Email       string    `json:"email"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}
	resp := userResponse{
		ID:          user.ID,
		Email:       user.Email,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		IsChirpyRed: user.IsChirpyRed,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Log in a user and return JWT + refresh token
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
	if err != nil || auth.CheckPasswordHash(user.HashedPassword, creds.Password) != nil {
		http.Error(w, `{"error": "Incorrect email or password"}`, http.StatusUnauthorized)
		return
	}

	// Generate tokens
	token, _ := auth.MakeJWT(user.ID, cfg.tokenSecret, time.Hour)
	refreshToken, _ := auth.MakeRefreshToken()

	// Store refresh token in DB
	cfg.db.InsertRefreshToken(r.Context(), database.InsertRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour), // 60 days
	})

	// Return tokens + user info
	type returnVals struct {
		Id            uuid.UUID `json:"id"`
		Created_at    time.Time `json:"created_at"`
		Updated_at    time.Time `json:"updated_at"`
		Email         string    `json:"email"`
		IsChirpyRed   bool      `json:"is_chirpy_red"`
		Token         string    `json:"token"`
		Refresh_token string    `json:"refresh_token"`
	}
	resp := returnVals{
		Id:            user.ID,
		Created_at:    user.CreatedAt,
		Updated_at:    user.UpdatedAt,
		Email:         user.Email,
		IsChirpyRed:   user.IsChirpyRed,
		Token:         token,
		Refresh_token: refreshToken,
	}
	dat, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

// Exchange a refresh token for a new JWT access token
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

// Revoke a refresh token (logout)
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

// Handle webhooks from Polka to upgrade a user to Chirpy Red
func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaKey {
		http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
		return
	}

	type webhookEvent struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	var event webhookEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, `{"error": "invalid webhook"}`, http.StatusBadRequest)
		return
	}

	if event.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	_, err = cfg.db.UpgradeUserToChirpyRed(r.Context(), event.Data.UserID)
	if err != nil {
		http.Error(w, `{"error": "user not found"}`, http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Extract necessary config values
	platform := os.Getenv("PLATFORM")
	tokenSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")
	dbURL := os.Getenv("DB_URL")

	// Connect to the PostgreSQL database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
	defer db.Close()

	// Create a Queries wrapper to access all database operations
	dbQueries := database.New(db)
	fmt.Println("Database connected and dbQueries ready!")

	// Initialize shared config
	apiCfg := &apiConfig{
		db:          dbQueries,
		platform:    platform,
		tokenSecret: tokenSecret,
		polkaKey:    polkaKey,
	}

	// Create HTTP mux and define all route handlers
	mux := http.NewServeMux()

	// Admin endpoints
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	// User authentication and profile endpoints
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUser)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)

	// Chirp posting and retrieval endpoints
	mux.HandleFunc("POST /api/chirps", apiCfg.postChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByID)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)

	// Health check endpoint
	mux.HandleFunc("GET /api/healthz", customHandler)

	// Webhook to handle third-party events (e.g. subscription upgrades)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaWebhookHandler)

	// Serve static frontend files from "/app", with visit tracking
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	// Start the HTTP server on port 8080
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
