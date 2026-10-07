package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Background pictures for the web UI come from Unsplash. The ring of the
// last cacheCount images is kept in the img/ directory. To make the UI show
// a picture immediately, every /api/next-background request serves the next
// cached image right away and refills the ring from Unsplash asynchronously;
// only when the cache is empty (e.g. very first run) is the download done
// synchronously, mirrored on the reference project (~/project/unsplash).
const (
	unsplashAccessKey = "cjjFLji7SSrb6iQ01Et3Z9iHFq9CmSosMQkl1lK3Ha4"

	cacheCount   = 50
	rateLimitErr = "Rate Limit Exceeded"
)

type unsplashPhoto struct {
	Urls struct {
		Regular string `json:"regular"`
	} `json:"urls"`
}

type backgroundService struct {
	apiBase string
	authKey string
	dir     string
	client  *http.Client

	cacheMu     sync.Mutex
	cacheSlot   int
	serveOffset int

	refreshMu   sync.Mutex
	refreshBusy bool
}

func newBackgroundService() *backgroundService {
	dir := os.Getenv("BG_CACHE_DIR")
	if dir == "" {
		dir = "img"
	}
	authKey := os.Getenv("UNSPLASH_ACCESS_KEY")
	if authKey == "" {
		authKey = unsplashAccessKey
	}
	return &backgroundService{
		apiBase: "https://api.unsplash.com",
		authKey: authKey,
		dir:     dir,
		client:  &http.Client{},
	}
}

func (b *backgroundService) cachePath(i int) string {
	return filepath.Join(b.dir, fmt.Sprintf("bg_%d.jpg", i))
}

func (b *backgroundService) saveToCache(data []byte, contentType string) {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()

	os.MkdirAll(b.dir, 0o755)

	ext := ".jpg"
	if strings.Contains(contentType, "png") {
		ext = ".png"
	}
	path := filepath.Join(b.dir, fmt.Sprintf("bg_%d%s", b.cacheSlot, ext))
	if err := os.WriteFile(path, data, 0o644); err == nil {
		b.cacheSlot = (b.cacheSlot + 1) % cacheCount
	}
}

func (b *backgroundService) serveNextCached(w http.ResponseWriter) bool {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()

	for i := 0; i < cacheCount; i++ {
		idx := (b.serveOffset + i) % cacheCount
		data, err := os.ReadFile(b.cachePath(idx))
		if err != nil {
			continue
		}
		b.serveOffset = idx + 1
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(data)
		return true
	}
	return false
}

// nextBackground answers with a background picture as fast as possible: it
// serves the next image from the img/ ring cache immediately and refills the
// ring from Unsplash in the background. When the cache is empty the download
// is done synchronously (the reference behaviour), so the very first request
// may be slower.
func (b *backgroundService) nextBackground(w http.ResponseWriter, r *http.Request) {
	if b.serveNextCached(w) {
		go b.refreshCache()
		return
	}

	data, contentType, err := b.fetchAndSave()
	if err != nil {
		if b.serveNextCached(w) {
			return
		}
		http.Error(w, "failed to fetch from unsplash: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	w.Write(data)
}

// refreshCache downloads one random photo from Unsplash and stores it in the
// ring cache. Concurrent calls collapse into a single in-flight download.
func (b *backgroundService) refreshCache() {
	b.refreshMu.Lock()
	defer b.refreshMu.Unlock()
	if b.refreshBusy {
		return
	}
	b.refreshBusy = true
	defer func() { b.refreshBusy = false }()

	b.fetchAndSave()
}

// fetchAndSave performs the reference download chain: pick a random photo,
// fetch its full image and add it to the ring cache.
func (b *backgroundService) fetchAndSave() ([]byte, string, error) {
	apiURL := b.apiBase + "/photos/random?query=nature&orientation=landscape"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Client-ID "+b.authKey)

	metaResp, err := b.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer metaResp.Body.Close()

	if metaResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(metaResp.Body)
		if strings.Contains(string(body), rateLimitErr) || metaResp.StatusCode == http.StatusTooManyRequests {
			return nil, "", errRateLimited
		}
		return nil, "", fmt.Errorf("unsplash error %d: %s", metaResp.StatusCode, body)
	}

	var photo unsplashPhoto
	if err := json.NewDecoder(metaResp.Body).Decode(&photo); err != nil {
		return nil, "", fmt.Errorf("failed to parse unsplash response: %w", err)
	}

	if photo.Urls.Regular == "" {
		return nil, "", fmt.Errorf("no image url in response")
	}

	imgResp, err := b.client.Get(photo.Urls.Regular)
	if err != nil {
		return nil, "", fmt.Errorf("failed to download image: %w", err)
	}
	defer imgResp.Body.Close()

	if imgResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("image download failed: %d", imgResp.StatusCode)
	}

	contentType := imgResp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		return nil, "", fmt.Errorf("unexpected content type %q", contentType)
	}

	imgData, err := io.ReadAll(imgResp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read image: %w", err)
	}

	b.saveToCache(imgData, contentType)

	return imgData, contentType, nil
}

var errRateLimited = errors.New("unsplash rate limit")
