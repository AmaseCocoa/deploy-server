package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	webhookSecret = os.Getenv("WEBHOOK_SECRET")
	deployScript  = os.Getenv("DEPLOY_SCRIPT")
	port          = getEnv("PORT", ":8080")
)

var (
	deployQueue = make(chan struct{}, 1)
	allowedIPs  []*net.IPNet
	ipMutex     sync.RWMutex
)

func getEnv(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func init() {
	updateAllowedIPs()
	go ipUpdater()
	go deployWorker()
}

func updateAllowedIPs() {
	resp, err := http.Get("https://api.github.com/meta")
	if err != nil {
		log.Printf("[ERROR] Failed to fetch GitHub meta: %v", err)
		return
	}
	defer resp.Body.Close()

	var meta struct {
		Hooks []string `json:"hooks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		log.Printf("[ERROR] Failed to decode GitHub meta: %v", err)
		return
	}

	var newIPs []*net.IPNet
	for _, cidr := range meta.Hooks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			newIPs = append(newIPs, ipNet)
		}
	}

	ipMutex.Lock()
	allowedIPs = newIPs
	ipMutex.Unlock()
	log.Printf("[INFO] Updated GitHub hooks IP list (%d ranges)", len(newIPs))
}

func ipUpdater() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		updateAllowedIPs()
	}
}

func isAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	ipMutex.RLock()
	defer ipMutex.RUnlock()
	for _, ipNet := range allowedIPs {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP != "" {
		clientIP = strings.Split(clientIP, ",")[0]
		clientIP = strings.TrimSpace(clientIP)
	} else {
		clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	if !isAllowed(clientIP) {
		log.Printf("[WARN] Blocked request from unauthorized IP: %s", clientIP)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if !verifySignature(payload, r.Header.Get("X-Hub-Signature-256")) {
		log.Println("[WARN] Invalid signature")
		http.Error(w, "Invalid signature", http.StatusForbidden)
		return
	}

	select {
	case deployQueue <- struct{}{}:
		log.Println("[INFO] Deployment queued")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, "Accepted")
	default:
		log.Println("[INFO] Busy: Deployment skipped")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "Busy")
	}
}

func verifySignature(payload []byte, signature string) bool {
	const prefix = "sha256="
	if len(signature) < len(prefix) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature[len(prefix):]), []byte(expected))
}

func deployWorker() {
	for range deployQueue {
		log.Println("[INFO] Deployment started...")

		cmd := exec.Command("bash", deployScript)
		out, err := cmd.CombinedOutput()

		if err != nil {
			log.Printf("[ERROR] Deployment failed: %v\nOutput: %s", err, string(out))
		} else {
			log.Printf("[SUCCESS] Deployment finished.\nOutput: %s", string(out))
		}
	}
}

func main() {
	log.Printf("[INFO] Server is running in %v", port)
	http.HandleFunc("/_github/deploy", handleWebhook)
	log.Fatal(http.ListenAndServe(port, nil))
}
