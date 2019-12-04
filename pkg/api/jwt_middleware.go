package api

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	"github.com/dgrijalva/jwt-go"
)

// Define our struct
type jwtMiddleware struct {
}

var tokenExtractor *regexp.Regexp = regexp.MustCompile("^ *Bearer (.*)$")

func extractTokenFromHeader(header string) string {
	str := tokenExtractor.FindStringSubmatch(header)
	if len(str) != 2 {
		return ""
	}
	return str[1]
}

var signingKey *rsa.PublicKey

func LoadSigningKey(fileName string) error {
	pub, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}

	signingKey, err = jwt.ParseRSAPublicKeyFromPEM(pub)
	if err != nil {
		return err
	}

	return nil
}

func authPublicKey(_ *jwt.Token) (interface{}, error) {
	return signingKey, nil
}

// Claims is JWT Token claims.
type Claims struct {
	jwt.StandardClaims
	Audience   []string `json:"aud,omitempty"`
	UID        string   `json:"uid"`
	Email      string   `json:"email"`
	Role       string   `json:"role"`
	Level      int      `json:"level"`
	State      string   `json:"state"`
	ReferralID string   `json:"referral_id"`
}

// Validator is JSON Web Token validator.
type Validator struct {
	Algorithm string `yaml:"algorithm"`
	Value     string `yaml:"value"`
}

// ValidateJWT validates, that JWT token is properly signed.
func (v *Validator) ValidateJWT(token *jwt.Token) (interface{}, error) {
	if token.Method.Alg() != v.Algorithm {
		return nil, errors.New("unexpected signing method")
	}

	publicKey, err := base64.StdEncoding.DecodeString(v.Value)
	if err != nil {
		return nil, err
	}

	signingKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	return signingKey, nil
}

// ParseJWT parses JSON Web Token and returns ready for use claims.
func ParseJWT(tokenStr string, keyFunc jwt.Keyfunc) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, keyFunc)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("claims: invalid jwt token")
	}

	return claims, nil
}

// Middleware function, which will be called for each request
func (amw *jwtMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("authorization")
		tokenStr := extractTokenFromHeader(authHeader)
		log.Printf("Token string: %s", tokenStr)

		claims, err := ParseJWT(tokenStr, authPublicKey)
		if err != nil {
			log.Printf("Authorization failed: %s", err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		log.Printf("Authenticated user %s (%s)\n", claims.Email, claims.UID)
		next.ServeHTTP(w, r)
	})
}
