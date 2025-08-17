package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// MCPOAuthClient handles OAuth flow for MCP resources
type MCPOAuthClient struct {
	ClientID     string
	BaseURL      string
	RedirectURI  string
	Scope        string
	httpClient   *http.Client
}

// PKCEChallenge holds PKCE challenge and verifier
type PKCEChallenge struct {
	CodeVerifier  string
	CodeChallenge string
}

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// MCPClaims represents the JWT claims for MCP tokens
type MCPClaims struct {
	TokenType string `json:"token_type"`
	Sub       string `json:"sub"`   // GitHub user ID
	Aud       string `json:"aud"`   // MCP scope
	Email     string `json:"email"` // User email (optional)
	jwt.RegisteredClaims
}

// ClientRegistrationRequest represents a dynamic client registration request
type ClientRegistrationRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scope        string   `json:"scope"`
}

// ClientRegistrationResponse represents the response from client registration
type ClientRegistrationResponse struct {
	ClientID               string   `json:"client_id"`
	ClientName             string   `json:"client_name"`
	RedirectURIs          []string `json:"redirect_uris"`
	Scope                 string   `json:"scope"`
	ExpiresAt             int64    `json:"expires_at"`
	RegistrationClientURI string   `json:"registration_client_uri"`
}

// NewMCPOAuthClient creates a new OAuth client
func NewMCPOAuthClient(clientID, baseURL, redirectURI, scope string) *MCPOAuthClient {
	return &MCPOAuthClient{
		ClientID:    clientID,
		BaseURL:     baseURL,
		RedirectURI: redirectURI,
		Scope:       scope,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// GeneratePKCE creates a PKCE challenge and verifier pair
func GeneratePKCE() (*PKCEChallenge, error) {
	// Generate 32 random bytes for code verifier
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	
	// Base64URL encode without padding
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	
	// Create SHA256 hash of verifier for challenge
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	challengeBytes := hasher.Sum(nil)
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeBytes)
	
	return &PKCEChallenge{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}, nil
}

// RegisterClient performs dynamic client registration with the OAuth server
func RegisterClient(baseURL, clientName string, redirectURIs []string, scope string) (*ClientRegistrationResponse, error) {
	regRequest := &ClientRegistrationRequest{
		ClientName:   clientName,
		RedirectURIs: redirectURIs,
		Scope:        scope,
	}

	jsonData, err := json.Marshal(regRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	resp, err := http.Post(baseURL+"/register", "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("client registration failed: %s", string(body))
	}

	var regResponse ClientRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResponse); err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %w", err)
	}

	return &regResponse, nil
}

// GetAuthorizationURL builds the OAuth authorization URL
func (c *MCPOAuthClient) GetAuthorizationURL(state string, pkce *PKCEChallenge) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":            {c.ClientID},
		"redirect_uri":         {c.RedirectURI},
		"scope":                {c.Scope},
		"state":                {state},
		"code_challenge":       {pkce.CodeChallenge},
		"code_challenge_method": {"S256"},
	}
	
	return fmt.Sprintf("%s/authorize?%s", c.BaseURL, params.Encode())
}

// ExchangeCodeForTokens exchanges authorization code for access and refresh tokens
func (c *MCPOAuthClient) ExchangeCodeForTokens(code string, pkce *PKCEChallenge) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURI},
		"client_id":     {c.ClientID},
		"code_verifier": {pkce.CodeVerifier},
	}
	
	resp, err := c.httpClient.PostForm(c.BaseURL+"/token", data)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}
	
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	
	return &tokenResp, nil
}

// RefreshTokens uses a refresh token to get new access and refresh tokens
func (c *MCPOAuthClient) RefreshTokens(refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ClientID},
	}
	
	resp, err := c.httpClient.PostForm(c.BaseURL+"/token", data)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token refresh failed: %s", string(body))
	}
	
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	
	return &tokenResp, nil
}

// TokenValidator handles JWT token validation for resource servers
type TokenValidator struct {
	jwksURL    string
	issuer     string
	audience   string
	httpClient *http.Client
	keySet     jwk.Set
}

// NewTokenValidator creates a new token validator
func NewTokenValidator(jwksURL, issuer, audience string) *TokenValidator {
	return &TokenValidator{
		jwksURL:    jwksURL,
		issuer:     issuer,
		audience:   audience,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// fetchJWKS fetches the JSON Web Key Set from the auth server
func (v *TokenValidator) fetchJWKS() error {
	resp, err := v.httpClient.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch failed with status: %d", resp.StatusCode)
	}
	
	keySet, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}
	
	v.keySet = keySet
	return nil
}

// ValidateToken validates a JWT access token
func (v *TokenValidator) ValidateToken(tokenString string) (*MCPClaims, error) {
	// Fetch JWKS if not already cached
	if v.keySet == nil {
		if err := v.fetchJWKS(); err != nil {
			return nil, err
		}
	}
	
	// Parse token without verification first to get key ID
	token, err := jwt.ParseWithClaims(tokenString, &MCPClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing key ID in token header")
		}
		
		// Find key in JWKS
		key, ok := v.keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key with ID %s not found in JWKS", kid)
		}
		
		// Convert to RSA public key
		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to get raw key: %w", err)
		}
		
		return rawKey, nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	
	claims, ok := token.Claims.(*MCPClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token or claims")
	}
	
	// Validate issuer
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, claims.Issuer)
	}
	
	// Validate audience
	if claims.Audience[0] != v.audience {
		return nil, fmt.Errorf("invalid audience: expected %s, got %s", v.audience, claims.Audience)
	}
	
	// Check token type
	if claims.TokenType != "access" {
		return nil, fmt.Errorf("invalid token type: expected access, got %s", claims.TokenType)
	}
	
	return claims, nil
}

// Example usage for MCP client
func ExampleMCPClient() {
	fmt.Println("Step 1: Register OAuth Client")
	
	// Register client with the OAuth server
	registration, err := RegisterClient(
		"https://auth.mcp.r167.dev",
		"My MCP Application",
		[]string{"https://your-app.com/callback"},
		"mcp:your-app.com:github-tools email",
	)
	if err != nil {
		fmt.Printf("Client registration failed: %v\n", err)
		return
	}
	
	fmt.Printf("Client registered successfully!\n")
	fmt.Printf("Client ID: %s\n", registration.ClientID)
	fmt.Printf("Expires at: %v\n", time.Unix(registration.ExpiresAt, 0))
	fmt.Println()
	
	fmt.Println("Step 2: Initialize OAuth Flow")
	
	// Initialize OAuth client with the registered client ID
	client := NewMCPOAuthClient(
		registration.ClientID,
		"https://auth.mcp.r167.dev",
		"https://your-app.com/callback",
		"mcp:your-app.com:github-tools email",
	)
	
	// Generate PKCE challenge
	pkce, err := GeneratePKCE()
	if err != nil {
		panic(err)
	}
	
	// Generate random state for CSRF protection
	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := base64.URLEncoding.EncodeToString(stateBytes)
	
	// Get authorization URL
	authURL := client.GetAuthorizationURL(state, pkce)
	fmt.Printf("Visit this URL to authorize: %s\n", authURL)
	
	// After user authorizes and returns with code...
	// authCode := "received_from_callback"
	// tokens, err := client.ExchangeCodeForTokens(authCode, pkce)
	// if err != nil {
	//     panic(err)
	// }
	
	// fmt.Printf("Access Token: %s\n", tokens.AccessToken)
	// fmt.Printf("Refresh Token: %s\n", tokens.RefreshToken)
}

// Example usage for MCP resource server
func ExampleResourceServer() {
	// Initialize token validator
	validator := NewTokenValidator(
		"https://auth.mcp.r167.dev/.well-known/jwks.json",
		"https://auth.mcp.r167.dev",
		"mcp:your-app.com:github-tools",
	)
	
	// In your HTTP handler
	http.HandleFunc("/api/resource", func(w http.ResponseWriter, r *http.Request) {
		// Extract Bearer token
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		
		token := strings.TrimPrefix(authHeader, "Bearer ")
		
		// Validate token
		claims, err := validator.ValidateToken(token)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}
		
		// Use claims
		userID := claims.Sub
		userEmail := claims.Email
		scope := claims.Audience[0]
		
		fmt.Printf("Authenticated user: %s (%s) with scope: %s\n", userID, userEmail, scope)
		
		// Return protected resource
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Access granted",
			"user_id": userID,
			"email":   userEmail,
			"scope":   scope,
		})
	})
}

func main() {
	fmt.Println("MCP OAuth Client Examples")
	fmt.Println("========================")
	
	// Run examples
	ExampleMCPClient()
	fmt.Println()
	ExampleResourceServer()
}