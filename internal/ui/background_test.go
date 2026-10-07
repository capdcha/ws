package ui

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var tinyJPG = []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0xff, 0xd9}

func newTestBackground(t *testing.T, apiBase string) *backgroundService {
	t.Helper()
	return &backgroundService{
		apiBase: apiBase,
		authKey: "test-key",
		dir:     t.TempDir(),
		client:  http.DefaultClient,
	}
}

// Seeding the ring cache is what makes cache-first serving instant on a real
// deployment (images already saved in the img/ directory).
func seedCache(t *testing.T, b *backgroundService, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(b.dir, fmt.Sprintf("bg_%d.jpg", i)), tinyJPG, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
}

// Empty cache: the reference chain is used, the image is downloaded and
// cached synchronously.
func TestBackgroundFetchAndCache(t *testing.T) {
	var calls int64
	var api *httptest.Server
	api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		switch r.URL.Path {
		case "/photos/random":
			if got := r.Header.Get("Authorization"); got != "Client-ID test-key" {
				t.Errorf("authorization = %q", got)
			}
			w.Write([]byte(`{"urls":{"regular":"` + api.URL + `/pic.jpg"}}`))
		case "/pic.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			w.Write(tinyJPG)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	b := newTestBackground(t, api.URL)
	rec := httptest.NewRecorder()
	b.nextBackground(rec, httptest.NewRequest("GET", "/api/next-background", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Fatalf("content-type = %q", ct)
	}
	if !bytes.Equal(rec.Body.Bytes(), tinyJPG) {
		t.Fatalf("body is not the image: %d bytes", rec.Body.Len())
	}
	if _, err := os.Stat(filepath.Join(b.dir, "bg_0.jpg")); err != nil {
		t.Fatalf("image was not cached: %v", err)
	}

	// Second request is served instantly from the cache; the background
	// refresh stores another picture into the next ring slot.
	rec = httptest.NewRecorder()
	b.nextBackground(rec, httptest.NewRequest("GET", "/api/next-background", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("second status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), tinyJPG) {
		t.Fatalf("second request was not served from cache")
	}
	waitForFile(t, filepath.Join(b.dir, "bg_1.jpg"))
	if atomic.LoadInt64(&calls) < 2 {
		t.Fatalf("background refresh did not download a fresh photo")
	}
}

// When the ring cache already contains images, they are served immediately
// and unsplash is not even contacted, regardless of its state.
func TestBackgroundServesCacheFirst(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unsplash must not be contacted while cache exists")
	}))
	defer api.Close()

	b := newTestBackground(t, api.URL)
	seedCache(t, b, 2)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		b.nextBackground(rec, httptest.NewRequest("GET", "/api/next-background", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, body = %s", i, rec.Code, rec.Body.String())
		}
		if !bytes.Equal(rec.Body.Bytes(), tinyJPG) {
			t.Fatalf("request %d: not served from cache", i)
		}
	}
	if b.serveOffset == 0 {
		t.Fatalf("ring cache was not rotated")
	}
}

// The rate-limit branch of the reference chain still maps to the cached ring
// (and never surfaces to the client) once images are available.
func TestBackgroundRateLimitKeepsServingCache(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"errors":["Rate Limit Exceeded"]}`)
	}))
	defer api.Close()

	b := newTestBackground(t, api.URL)
	seedCache(t, b, 1)

	rec := httptest.NewRecorder()
	b.nextBackground(rec, httptest.NewRequest("GET", "/api/next-background", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from cache", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), tinyJPG) {
		t.Fatalf("not served from cache")
	}
}

// Nothing cached and no upstream: a plain 502, no broken image.
func TestBackgroundUnavailable(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer api.Close()

	b := newTestBackground(t, api.URL)
	rec := httptest.NewRecorder()
	b.nextBackground(rec, httptest.NewRequest("GET", "/api/next-background", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

// The UI route is registered and reachable for both roles.
func TestNextBackgroundRoute(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer api.Close()

	s := &Server{
		apiBase: api.URL,
		client:  http.DefaultClient,
		tickets: newTicketStore(),
		bg:      newTestBackground(t, api.URL),
	}
	for _, addr := range []string{"127.0.0.1:40000", "203.0.113.9:40000"} {
		rec := do(t, s.Routes(), "/api/next-background", addr)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("from %s: status = %d, want 502 (cache empty)", addr, rec.Code)
		}
	}
}
