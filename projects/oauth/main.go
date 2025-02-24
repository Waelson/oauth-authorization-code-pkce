package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
)

// Configuração do OAuth
const (
	clientID     = "1084790336194-a71dqkqnl92kq3lqai48p1dbda8haus7.apps.googleusercontent.com" // 🔹 Armazenado no backend
	clientSecret = "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"                                       // 🔹 Nunca exposto ao frontend
	redirectURI  = "http://localhost:3000/callback"
	tokenURL     = "https://oauth2.googleapis.com/token"
)

// Estrutura para capturar a requisição do frontend
type TokenRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

// Estrutura para armazenar a resposta do Google
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// Middleware para habilitar CORS
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		log.Println("📢 CORS Middleware: Request recebido de", origin)

		// Definição das origens permitidas
		allowedOrigins := map[string]bool{
			"http://localhost:3000": true,
			"http://localhost:3001": true,
		}

		// Se a origem da requisição estiver na lista, permite o acesso
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			log.Println("❌ Origem não permitida:", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Se for um preflight request, responder diretamente e retornar
		if r.Method == "OPTIONS" {
			log.Println("⚠️ OPTIONS request recebido, respondendo 204 No Content")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// Função para trocar o código de autorização pelo access_token
func exchangeCodeForToken(code, codeVerifier string) (*TokenResponse, error) {
	log.Println("🔄 Iniciando troca de código por token no Google OAuth")
	log.Println("📌 Código recebido:", code)
	log.Println("📌 Code Verifier recebido:", codeVerifier)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("code_verifier", codeVerifier)

	// Faz a requisição ao Google
	log.Println("🚀 Enviando requisição para:", tokenURL)
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		log.Println("❌ Erro ao enviar requisição ao Google:", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Println("✅ Resposta do Google recebida. Status:", resp.Status)

	// Decodifica a resposta JSON do Google
	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Println("❌ Erro ao decodificar resposta JSON:", err)
		return nil, err
	}

	log.Println("🔑 Token de acesso recebido:", tokenResponse.AccessToken[:10]+"...") // Mostra apenas os primeiros caracteres
	log.Println("🕒 Tempo de expiração:", tokenResponse.ExpiresIn, "segundos")

	return &tokenResponse, nil
}

// Endpoint para receber o código e retornar o token ao frontend
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("📩 Recebida requisição para /token de:", r.RemoteAddr)

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println("❌ Erro ao decodificar JSON da requisição:", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Println("📌 Código de autorização recebido:", req.Code)
	log.Println("📌 Code Verifier recebido:", req.CodeVerifier)

	if req.Code == "" || req.CodeVerifier == "" {
		log.Println("⚠️ Código ou Code Verifier ausente!")
		http.Error(w, "Missing code or code_verifier", http.StatusBadRequest)
		return
	}

	// Faz a troca pelo access_token
	token, err := exchangeCodeForToken(req.Code, req.CodeVerifier)
	if err != nil {
		log.Println("❌ Erro ao trocar código por token:", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Retorna o token ao frontend
	log.Println("📤 Enviando token de acesso ao cliente")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4000"
	}

	// Registra o endpoint com CORS habilitado
	http.HandleFunc("/token", enableCORS(tokenHandler))

	log.Println("🚀 Servidor rodando em http://localhost:" + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
