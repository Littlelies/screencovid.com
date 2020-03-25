// Package http provides a set of HTTP Cloud Functions samples.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"cloud.google.com/go/storage"
)

const LIMIT int64 = 32768 // Limits the POST data size to avoid memory issues
const recaptchaServerName = "https://www.google.com/recaptcha/api/siteverify"

type answers struct {
	Question1 string `json:"q1"`
	Question2 string `json:"q2"`
}

type serverRequest struct {
	ReCaptchaToken string          `json:"captcha_token"`
	ID             string          `json:"id"`
	Answers        json.RawMessage `json:"answers"`
}

type serverResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type recaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

func jsonResponse(w http.ResponseWriter, c int, d interface{}) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func checkRecaptchaToken(remoteip, response string) (recaptchaResponse, error) {
	var r recaptchaResponse
	resp, err := http.PostForm(recaptchaServerName,
		url.Values{"secret": {recaptchaPrivateKey}, "remoteip": {remoteip}, "response": {response}})
	if err != nil {
		return r, fmt.Errorf("Post to recaptcha error %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return r, fmt.Errorf("Read error: could not read body %s", err)
	}
	err = json.Unmarshal(body, &r)
	if err != nil {
		return r, fmt.Errorf("Read error: got invalid JSON %s", err)
	}
	return r, nil
}

//var client *storage.Client
var bucket *storage.BucketHandle
var ctx context.Context
var recaptchaPrivateKey string
var recaptchaBypass string

func init() {
	// Get variables
	bucketName := os.Getenv("BUCKET_NAME")
	if bucketName == "" {
		fmt.Fprintf(os.Stderr, "BUCKET_NAME environment variable must be set.\n")
		os.Exit(1)
	}
	recaptchaPrivateKey = os.Getenv("RECAPTCHA_PRIVATE_KEY")
	recaptchaBypass = os.Getenv("RECAPTCHA_BYPASS")

	ctx = context.Background()
	// Creates a client.
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	// Creates a Bucket instance.
	bucket = client.Bucket(bucketName)
}

func addRecord(id string, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*50)
	defer cancel()
	wc := bucket.Object(id).NewWriter(ctx)
	if _, err := io.Copy(wc, bytes.NewReader(payload)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return nil
}

// CORSEnabledFunctionAuth is an example of setting CORS headers with
// authentication enabled.
// For more information about CORS and CORS preflight requests, see
// https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request.
func CORSEnabledFunctionAuth(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers for the preflight request
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Origin", "https://screencovid.com")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Set CORS headers for the main request.
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Origin", "https://screencovid.com")
	// Parse request from body
	var t serverRequest
	data, err := ioutil.ReadAll(io.LimitReader(r.Body, LIMIT))
	if err != nil {
		log.Println(err)
		jsonResponse(w, http.StatusBadRequest, serverResponse{Status: "error", Message: "must supply a payload"})
		return
	}
	err = json.Unmarshal(data, &t)
	if err != nil {
		log.Println(err)
		jsonResponse(w, http.StatusBadRequest, serverResponse{Status: "error", Message: "error parsing input"})
		return
	}
	// Check reCaptcha score
	if recaptchaPrivateKey != "" && (recaptchaBypass == "" || t.ReCaptchaToken != recaptchaBypass) {
		recaptchaResponse, err := checkRecaptchaToken(t.ReCaptchaToken, r.Header.Get("X-Forwarded-For"))
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, serverResponse{Status: "error", Message: err.Error()})
			return
		}
		if !recaptchaResponse.Success {
			jsonResponse(w, http.StatusBadRequest, serverResponse{Status: "error", Message: "recaptcha thinks your are a bot"})
		}
	}
	// Add to database
	answers, _ := json.Marshal(t.Answers)
	currentTime := time.Now().Format("2006/01/02/15/04/")
	err = addRecord(currentTime+t.ID, answers)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, serverResponse{Status: "error", Message: "failed to upload data " + err.Error()})
		return
	}
	// Answer
	jsonResponse(w, http.StatusOK, serverResponse{Status: "ok", Message: "thank you"})
}
