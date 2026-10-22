package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

type Config struct {
	Provider   string   `json:"provider"`
	APIKey     string   `json:"api_key"`
	BaseURL    string   `json:"base_url"`
	Model      string   `json:"model"`
	System     string   `json:"system"`
	Port       int      `json:"port"`
	AutoOpen   bool     `json:"autoopen"`
	AllowShell *bool    `json:"allow_shell"`
	MaxTokens  int      `json:"max_tokens"`
	Fallback   []string `json:"fallback_models"`
	Models     []string `json:"models"`
}

type Msg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

var (
	cfg    Config
	mu     sync.Mutex
	hist   []Msg
	modDir string
	home   string

	evMu   sync.Mutex
	evSubs = map[chan []byte]struct{}{}

	actMu       sync.Mutex
	lastActions []string
)

type event struct {
	Type        string   `json:"type"`
	Text        string   `json:"text,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
	ID          int      `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Label       string   `json:"label,omitempty"`
	Result      string   `json:"result,omitempty"`
	State       string   `json:"state,omitempty"`
}

var toolSeq int64

func nextToolID() int {
	return int(atomic.AddInt64(&toolSeq, 1))
}

// truncate cuts by runes, not bytes.
// A CJK character is 3 bytes; slicing by byte splits the UTF-8 sequence
// and produces mojibake (seen on device with screen node labels).
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

func broadcast(e event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	evMu.Lock()
	for ch := range evSubs {
		select {
		case ch <- b:
		default:
		}
	}
	evMu.Unlock()
}

func status(format string, a ...interface{}) {
	txt := fmt.Sprintf(format, a...)
	if txt == "" {
		return
	}
	log.Printf("[status] %s", txt)
	broadcast(event{Type: "status", Text: txt})
}

func noteAction(name string) {
	actMu.Lock()
	lastActions = append(lastActions, name)
	actMu.Unlock()
}

func resetActions() {
	actMu.Lock()
	lastActions = nil
	actMu.Unlock()
}

func snapshotActions() []string {
	actMu.Lock()
	defer actMu.Unlock()
	out := make([]string, len(lastActions))
	copy(out, lastActions)
	return out
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := make(chan []byte, 32)
	evMu.Lock()
	evSubs[ch] = struct{}{}
	evMu.Unlock()
	defer func() {
		evMu.Lock()
		delete(evSubs, ch)
		evMu.Unlock()
	}()

	fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
	fl.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		}
	}
}

// Android dengan Private DNS (DoT) tidak menyediakan resolver loopback
// (127.0.0.1:53/[::1]:53) dan /etc/resolv.conf tidak ada, sehingga resolver
// murni Go gagal. Dial kustom meminta DNS publik secara langsung.
func init() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			servers := []string{
				"8.8.8.8:53",
				"8.8.4.4:53",
				"1.1.1.1:53",
				"1.0.0.1:53",
				"94.140.14.14:53",
				"192.168.100.1:53",
			}
			var lastErr error
			for _, s := range servers {
				d := net.Dialer{Timeout: 3 * time.Second}
				c, err := d.DialContext(ctx, "udp", s)
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

func httpClient(timeout time.Duration) *http.Client {
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(filepath.Join(modDir, "cacert.pem")); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// configPath is the user-editable config location.
// It lives in home (/data/adb/aiagent/) rather than the module dir so that
// flashing a module update does not overwrite the user configuration.
func configPath() string {
	return filepath.Join(home, "config.json")
}

func loadConfig() {
	// Prefer the user config; fall back to the factory template shipped in the
	// module directory, which is where older versions stored the config.
	candidates := []string{configPath(), filepath.Join(modDir, "config.json")}
	var (
		b    []byte
		err  error
		used string
	)
	for _, p := range candidates {
		if b, err = os.ReadFile(p); err == nil {
			used = p
			break
		}
	}
	// Default to auto-opening the chat UI. Set before reading the file so a config
	// without an autoopen field keeps it true (it used to be set only on success).
	cfg.AutoOpen = true
	if used == "" {
		// This used to return early, which skipped every default when the config file
		// was missing — most visibly Port stayed 0 and the server bound to a random
		// port, so the UI could never connect. Log and fall through to defaults now.
		log.Printf("config read error: %v (using defaults)", err)
	} else {
		log.Printf("config loaded: %s", used)
		if e := json.Unmarshal(b, &cfg); e != nil {
			log.Printf("config parse error: %v", e)
		}
	}
	prov := strings.ToLower(strings.TrimSpace(cfg.Provider))
	switch prov {
	case "", "gemini", "google":
		prov = "gemini"
	case "openrouter", "openai-compatible", "openai_compatible", "openai", "oaicompat":
		prov = "openai"
	}
	cfg.Provider = prov
	if cfg.BaseURL == "" {
		if cfg.Provider == "openai" {
			cfg.BaseURL = "https://openrouter.ai/api/v1"
		} else {
			cfg.BaseURL = "https://generativelanguage.googleapis.com/v1beta"
		}
	}
	if cfg.Model == "" {
		if cfg.Provider == "openai" {
			cfg.Model = "google/gemini-2.5-flash-lite"
		} else {
			cfg.Model = "gemini-2.5-flash"
		}
	}
	if len(cfg.Fallback) == 0 {
		if cfg.Provider == "openai" {
			cfg.Fallback = []string{"nvidia/nemotron-3.5-lightning:free"}
		} else {
			cfg.Fallback = []string{"gemini-2.5-flash-lite"}
		}
	}
	if cfg.Port == 0 {
		cfg.Port = 8787
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 1024
	}
	if len(cfg.Models) == 0 {
		if cfg.Provider == "openai" {
			cfg.Models = []string{
				"google/gemini-2.5-flash-lite",
				"google/gemini-2.5-flash",
				"google/gemini-3.1-flash-lite",
				"google/gemini-3.5-flash-lite",
				"nvidia/nemotron-3.5-lightning:free",
				"nvidia/nemotron-3-super-120b-a12b:free",
				"google/gemma-4-31b-it:free",
			}
		} else {
			cfg.Models = append([]string{cfg.Model}, cfg.Fallback...)
		}
	}
	if cfg.System == "" {
		cfg.System = "You are an autonomous AI AGENT running as root on the user's Android phone (Indonesian user). " +
			"You act on the phone ONLY by calling tools/functions. " +
			"RULE 1: You CANNOT do anything by writing text - to open an app, write/read/move/delete files, run commands, you MUST call the matching tool; never claim an action is done unless you actually called the tool. " +
			"RULE 2: The word 'buka' is CONTEXTUAL - decide the target: a file/folder/path -> open_path, a web link -> open_url, an installed app name -> open_app. Do NOT assume 'buka' always means an app. " +
			"RULE 3: Chain multiple tool calls until the task is finished (e.g. make_dir -> write_file -> read_file), then summarize briefly. " +
			"Tools: open_app (app), open_path (file/folder), open_url, web_search, run_shell (root), write_file, read_file, list_dir, make_dir, move_file, delete_path, download_url, schedule_message (auto reminder after N seconds; use delay_seconds). " +
			"SCREEN TOOLS: screen (read current UI tree with tap coordinates), tap (x,y from screen), swipe, key (HOME/BACK/ENTER/...), text (type into focused field), screenshot (save PNG). " +
			"Default save location: /storage/emulated/0/Download. Always use absolute paths. Reply concisely in Indonesian. " +
			"FINALLY: on the very last line of every answer, add exactly one line starting with 'SARAN:' followed by 2-4 short follow-up actions the user may want next, separated by ' | ' (Bahasa Indonesia, no quotes). Example: 'SARAN: Buka file hasil unduhan | Lihat folder Download | Cek sisa storage'."
	}
}

func saveConfig() {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	// 0600: the file holds the API key, keep it away from other apps
	if err := os.WriteFile(configPath(), b, 0600); err != nil {
		log.Printf("config save error: %v", err)
	}
}

func setModel(m string) bool {
	m = strings.TrimSpace(m)
	if m == "" {
		return false
	}
	mu.Lock()
	cfg.Model = m
	mu.Unlock()
	saveConfig()
	log.Printf("[model] switched to %s", m)
	return true
}

// randomModel memilih model acak dari daftar (hindari model yang sama berturut-turut).
func randomModel() string {
	mu.Lock()
	list := append([]string(nil), cfg.Models...)
	cur := cfg.Model
	mu.Unlock()
	if len(list) == 0 {
		return cur
	}
	if len(list) == 1 {
		return list[0]
	}
	pick := list[rand.IntN(len(list))]
	for i := 0; i < 8 && pick == cur; i++ {
		pick = list[rand.IntN(len(list))]
	}
	return pick
}

func historyPath() string { return filepath.Join(home, "history.json") }

func loadHistory() {
	if b, err := os.ReadFile(historyPath()); err == nil {
		json.Unmarshal(b, &hist)
	}
}

func saveHistory() {
	b, _ := json.MarshalIndent(hist, "", " ")
	os.WriteFile(historyPath(), b, 0600)
}

func notify(title, text, url string) {
	if url == "" {
		return
	}
	// Give up when the app is not installed. Otherwise am start retries 30 times
	// at 4s intervals and floods the log (module kept, app uninstalled is common).
	if out, err := exec.Command("pm", "list", "packages", "com.zafxyra.agent").Output(); err != nil ||
		!strings.Contains(string(out), "com.zafxyra.agent") {
		log.Printf("notify skipped: com.zafxyra.agent not installed")
		return
	}
	// Jaga-jaga: pastikan app boleh posting notif (bisa ke-reset setelah reinstall)
	for _, g := range [][]string{
		{"pm", "grant", "com.zafxyra.agent", "android.permission.POST_NOTIFICATIONS"},
		{"appops", "set", "com.zafxyra.agent", "START_FOREGROUND", "allow"},
		{"appops", "set", "com.zafxyra.agent", "POST_NOTIFICATION", "allow"},
	} {
		exec.Command(g[0], g[1:]...).Run()
	}
	// Retry: PMS/user belum siap tepat setelah boot ('Activity class does not exist').
	// Bounded to 8 attempts with growing delays instead of spinning forever.
	for i := 0; i < 8; i++ {
		out, err := exec.Command("am", "start", "-n", "com.zafxyra.agent/.MainActivity",
			"--es", "url", url, "--ez", "boot", "true").CombinedOutput()
		s := string(out)
		if err == nil && !strings.Contains(s, "Error") && !strings.Contains(s, "does not exist") {
			return
		}
		log.Printf("am start attempt %d: %s", i+1, strings.TrimSpace(s))
		time.Sleep(time.Duration(2+i) * time.Second)
	}
}

func callLLM(msgs []Msg) (string, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return "", fmt.Errorf("API key not set. Put it in %s and restart the module (or set it in the chat UI).", configPath())
	}
	if cfg.Provider == "openai" {
		return callOpenAI(msgs)
	}
	return callGemini(msgs)
}

type gemFn struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}
type gemFnResp struct {
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response"`
}
type gemPart struct {
	Text             string     `json:"text,omitempty"`
	FunctionCall     *gemFn     `json:"functionCall,omitempty"`
	FunctionResponse *gemFnResp `json:"functionResponse,omitempty"`
}
type gemContent struct {
	Role  string    `json:"role"`
	Parts []gemPart `json:"parts"`
}

func doGemini(model string, contents []gemContent, sys string, tools []interface{}, force bool) (string, []gemFn, int, string, error) {
	reqBody := map[string]interface{}{"contents": contents}
	if sys != "" {
		reqBody["systemInstruction"] = map[string]interface{}{"parts": []gemPart{{Text: sys}}}
	}
	if len(tools) > 0 {
		reqBody["tools"] = tools
		if force {
			reqBody["toolConfig"] = map[string]interface{}{
				"functionCallingConfig": map[string]interface{}{"mode": "ANY"},
			}
		}
	}
	jb, _ := json.Marshal(reqBody)
	url := fmt.Sprintf("%s/models/%s:generateContent", strings.TrimRight(cfg.BaseURL, "/"), model)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jb))
	if err != nil {
		return "", nil, 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", cfg.APIKey)
	resp, err := httpClient(120 * time.Second).Do(req)
	if err != nil {
		return "", nil, 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, resp.StatusCode, string(body), nil
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []gemPart `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", nil, resp.StatusCode, string(body), err
	}
	if len(out.Candidates) == 0 {
		return "", nil, resp.StatusCode, string(body), nil
	}
	var sb strings.Builder
	var calls []gemFn
	for _, p := range out.Candidates[0].Content.Parts {
		if p.Text != "" {
			sb.WriteString(p.Text)
		}
		if p.FunctionCall != nil {
			calls = append(calls, *p.FunctionCall)
		}
	}
	return sb.String(), calls, resp.StatusCode, "", nil
}

func pickModel() string {
	url := strings.TrimRight(cfg.BaseURL, "/") + "/models?pageSize=200"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("x-goog-api-key", cfg.APIKey)
	resp, err := httpClient(30 * time.Second).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var out struct {
		Models []struct {
			Name    string   `json:"name"`
			Methods []string `json:"supportedGenerationMethods"`
		} `json:"models"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return ""
	}
	hasGen := func(methods []string) bool {
		for _, me := range methods {
			if me == "generateContent" {
				return true
			}
		}
		return false
	}
	for _, m := range out.Models {
		n := strings.TrimPrefix(m.Name, "models/")
		if hasGen(m.Methods) && strings.Contains(n, "flash") && !strings.Contains(n, "exp") && !strings.Contains(n, "thinking") {
			return n
		}
	}
	for _, m := range out.Models {
		if hasGen(m.Methods) {
			return strings.TrimPrefix(m.Name, "models/")
		}
	}
	return ""
}

const maxAgentSteps = 8

func geminiAgent(model string, msgs []Msg) (string, int, string, error) {
	contents := []gemContent{}
	var sys string
	for _, m := range msgs {
		switch m.Role {
		case "system":
			sys = m.Content
		case "assistant":
			contents = append(contents, gemContent{Role: "model", Parts: []gemPart{{Text: m.Content}}})
		default:
			contents = append(contents, gemContent{Role: "user", Parts: []gemPart{{Text: m.Content}}})
		}
	}
	tools := toolDecls()
	force := looksLikeCommand(lastUserMsg(msgs))
	for step := 0; step < maxAgentSteps; step++ {
		text, calls, status, body, err := doGemini(model, contents, sys, tools, force && step == 0)
		if err != nil {
			return "", 0, "", err
		}
		if status < 200 || status >= 300 {
			return "", status, body, nil
		}
		if len(calls) == 0 {
			return text, status, "", nil
		}
		// Langkah agent: eksekusi tool, kirim hasilnya balik ke model, ulangi.
		var cparts []gemPart
		var rparts []gemPart
		for i := range calls {
			c := calls[i]
			cparts = append(cparts, gemPart{FunctionCall: &c})
			out := execTool(c.Name, c.Args)
			rparts = append(rparts, gemPart{FunctionResponse: &gemFnResp{Name: c.Name, Response: map[string]interface{}{"result": out}}})
		}
		contents = append(contents, gemContent{Role: "model", Parts: cparts})
		contents = append(contents, gemContent{Role: "user", Parts: rparts})
	}
	return "Maaf, tugasnya butuh terlalu banyak langkah. Coba pecah jadi perintah yang lebih kecil.", 200, "", nil
}

func callGemini(msgs []Msg) (string, error) {
	text, status, body, err := geminiAgent(cfg.Model, msgs)
	if err != nil {
		return "", err
	}
	if status >= 200 && status < 300 {
		if text != "" {
			return text, nil
		}
		return "", fmt.Errorf("empty response: %s", body)
	}
	if status == 404 {
		if pm := pickModel(); pm != "" && pm != cfg.Model {
			log.Printf("model %s unavailable, retrying with %s", cfg.Model, pm)
			t2, s2, b2, e2 := geminiAgent(pm, msgs)
			if e2 != nil {
				return "", e2
			}
			if s2 >= 200 && s2 < 300 && t2 != "" {
				return t2, nil
			}
			body = b2
		}
	}
	return "", fmt.Errorf("HTTP %d: %s", status, body)
}

func toolDecls() []interface{} {
	funcs := []interface{}{
		map[string]interface{}{
			"name":        "open_app",
			"description": "Buka (launch) sebuah aplikasi di HP pengguna berdasarkan namanya (mis. WhatsApp, YouTube, Instagram) atau nama package (mis. com.whatsapp).",
			"parameters": map[string]interface{}{
				"type": "OBJECT",
				"properties": map[string]interface{}{
					"app": map[string]interface{}{"type": "STRING", "description": "nama aplikasi atau nama package"},
				},
				"required": []string{"app"},
			},
		},
		map[string]interface{}{
			"name":        "open_url",
			"description": "Buka sebuah URL/tautan di browser HP pengguna. Tambahkan https:// bila tidak ada.",
			"parameters": map[string]interface{}{
				"type": "OBJECT",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{"type": "STRING", "description": "URL yang akan dibuka"},
				},
				"required": []string{"url"},
			},
		},
		map[string]interface{}{
			"name":        "web_search",
			"description": "Cari sesuatu di Google dan buka hasil pencariannya di browser HP.",
			"parameters": map[string]interface{}{
				"type": "OBJECT",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{"type": "STRING", "description": "kata kunci pencarian"},
				},
				"required": []string{"query"},
			},
		},
	}
	if shellAllowed() {
		funcs = append(funcs, map[string]interface{}{
			"name": "run_shell",
			"description": "Jalankan perintah shell di HP pengguna (root) dan kembalikan output. " +
				"Pakai HANYA saat pengguna minta menjalankan perintah/shell, cek sistem, kelola file, atau tugas teknis. " +
				"Contoh: 'cek storage', 'list file Download', 'sisa baterai', 'pm list packages | grep wa'.",
			"parameters": map[string]interface{}{
				"type": "OBJECT",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{"type": "STRING", "description": "perintah shell yang dijalankan via sh -c"},
				},
				"required": []string{"command"},
			},
		})
	}
	gemStr := func(desc string) map[string]interface{} {
		return map[string]interface{}{"type": "STRING", "description": desc}
	}
	gemTool := func(name, desc string, props map[string]interface{}, required []string) map[string]interface{} {
		return map[string]interface{}{
			"name": name, "description": desc,
			"parameters": map[string]interface{}{"type": "OBJECT", "properties": props, "required": required},
		}
	}
	funcs = append(funcs,
		gemTool("write_file", "Tulis/buat file baru di HP (menimpa bila sudah ada); folder induk dibuat otomatis. Gunakan path absolut, mis. /storage/emulated/0/Download/note.txt.", map[string]interface{}{"path": gemStr("path absolut file"), "content": gemStr("isi file")}, []string{"path", "content"}),
		gemTool("read_file", "Baca isi sebuah file teks di HP. Gunakan path absolut.", map[string]interface{}{"path": gemStr("path absolut file")}, []string{"path"}),
		gemTool("list_dir", "Tampilkan daftar file/folder pada sebuah direktori di HP.", map[string]interface{}{"path": gemStr("path direktori, mis. /storage/emulated/0/Download")}, []string{"path"}),
		gemTool("make_dir", "Buat folder (beserta folder induknya) di HP.", map[string]interface{}{"path": gemStr("path folder")}, []string{"path"}),
		gemTool("move_file", "Pindahkan atau ganti nama file/folder di HP.", map[string]interface{}{"from": gemStr("path sumber"), "to": gemStr("path tujuan")}, []string{"from", "to"}),
		gemTool("delete_path", "Hapus file atau folder di HP.", map[string]interface{}{"path": gemStr("path yang akan dihapus")}, []string{"path"}),
		gemTool("download_url", "Unduh file dari internet lalu simpan ke path di HP.", map[string]interface{}{"url": gemStr("URL file yang diunduh"), "path": gemStr("path tujuan penyimpanan")}, []string{"url", "path"}),
		gemTool("open_path", "Buka sebuah FILE atau FOLDER di HP dengan aplikasi penampil/pengelola bawaan. Pakai untuk permintaan seperti 'buka file catatan.txt', 'buka folder Download', 'buka foto/video/musik'. BUKAN untuk aplikasi; untuk aplikasi pakai open_app.", map[string]interface{}{"path": gemStr("path absolut file atau folder, mis. /storage/emulated/0/Download/catatan.txt")}, []string{"path"}),
		gemTool("schedule_message", "Jadwalkan PESAN OTOMATIS dari agent ke pengguna setelah jeda waktu tertentu (pengingat/reminder). Agent mengirim pesan ini sendiri tanpa ditanya lagi. Pakai saat pengguna minta diingatkan sesuatu, mis. 'ingetin 10 menit lagi minum obat'.", map[string]interface{}{"delay_seconds": map[string]interface{}{"type": "INTEGER", "description": "jeda waktu dalam detik sebelum pesan dikirim"}, "message": gemStr("isi pesan pengingat yang akan dikirim nanti")}, []string{"delay_seconds", "message"}),
		// ---- UI automation: let the agent actually operate the screen, not just launch apps ----
		gemTool("screen", "Read the current UI tree and return clickable nodes with their center coordinates. Prefer this over screenshots when you need to see the screen, find a button, or confirm the previous action took effect.", map[string]interface{}{}, []string{}),
		gemTool("tap", "Tap screen coordinates. Coordinates must come from the @(x,y) values returned by screen; do not guess. duration_ms>=400 is treated as a long press.", map[string]interface{}{"x": map[string]interface{}{"type": "INTEGER", "description": "x coordinate"}, "y": map[string]interface{}{"type": "INTEGER", "description": "y coordinate"}, "duration_ms": map[string]interface{}{"type": "INTEGER", "description": "hold duration in ms, default 80; >=400 means long press"}}, []string{"x", "y"}),
		gemTool("swipe", "Swipe across the screen to scroll lists, change pages, or pull down the notification shade.", map[string]interface{}{"x1": map[string]interface{}{"type": "INTEGER", "description": "start x"}, "y1": map[string]interface{}{"type": "INTEGER", "description": "start y"}, "x2": map[string]interface{}{"type": "INTEGER", "description": "end x"}, "y2": map[string]interface{}{"type": "INTEGER", "description": "end y"}, "duration_ms": map[string]interface{}{"type": "INTEGER", "description": "swipe duration in ms, default 300"}}, []string{"x1", "y1", "x2", "y2"}),
		gemTool("key", "Send a key event such as back, home, enter, or delete.", map[string]interface{}{"key": gemStr("HOME/BACK/ENTER/POWER/TAB/DEL/MENU/RECENT/VOLUP/VOLDOWN, or a numeric keycode")}, []string{"key"}),
		gemTool("text", "Type text into the focused input field. Uses ADBKeyboard when available for full Unicode; otherwise falls back to input text, which is ASCII-only.", map[string]interface{}{"text": gemStr("text to type")}, []string{"text"}),
		gemTool("screenshot", "Capture the screen to a PNG file and return its path. Only use this when screen cannot describe the UI (pure graphics).", map[string]interface{}{"path": gemStr("save path; defaults to /storage/emulated/0/Download")}, []string{}),
	)
	return []interface{}{
		map[string]interface{}{"functionDeclarations": funcs},
	}
}

var appAliases = map[string]string{
	"whatsapp": "com.whatsapp", "wa": "com.whatsapp",
	"youtube": "com.google.android.youtube", "yt": "com.google.android.youtube",
	"chrome": "com.android.chrome", "browser": "com.android.chrome",
	"instagram": "com.instagram.android", "ig": "com.instagram.android",
	"tiktok":   "com.zhiliaoapp.musically",
	"telegram": "org.telegram.messenger",
	"facebook": "com.facebook.katana", "fb": "com.facebook.katana",
	"gmail":     "com.google.android.gm",
	"maps":      "com.google.android.apps.maps",
	"spotify":   "com.spotify.music",
	"netflix":   "com.netflix.mediaclient",
	"shopee":    "com.shopee.id",
	"tokopedia": "com.tokopedia.tkpd",
	"gojek":     "com.gojek.app",
	"grab":      "com.grabtaxi.passenger",
	"dana":      "id.dana", "ovo": "id.co.ovo",
	"settings": "com.android.settings", "pengaturan": "com.android.settings",
	"kalkulator": "com.coloros.calculator", "calculator": "com.coloros.calculator",
}

var (
	pkgCache []string
	pkgMu    sync.Mutex
)

func installedPackages() []string {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	if pkgCache != nil {
		return pkgCache
	}
	out, _ := exec.Command("pm", "list", "packages").Output()
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "package:"))
		if l != "" {
			pkgCache = append(pkgCache, l)
		}
	}
	return pkgCache
}

func refreshPackages() {
	pkgMu.Lock()
	pkgCache = nil
	pkgMu.Unlock()
	installedPackages()
}

func isInstalled(pkg string) bool {
	for _, p := range installedPackages() {
		if p == pkg {
			return true
		}
	}
	return false
}

func resolvePackage(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, pre := range []string{"aplikasi ", "app ", "the ", "buka "} {
		n = strings.TrimPrefix(n, pre)
	}
	n = strings.TrimSuffix(n, " app")
	if n == "" {
		return ""
	}
	if strings.Contains(n, ".") && !strings.ContainsAny(n, " ") {
		return n
	}
	if p, ok := appAliases[n]; ok && isInstalled(p) {
		return p
	}
	find := func(list []string) string {
		var best string
		for _, p := range list {
			short := p
			if i := strings.LastIndex(p, "."); i >= 0 {
				short = p[i+1:]
			}
			if short == n || strings.Contains(short, n) || strings.Contains(p, n) {
				if best == "" || len(p) < len(best) {
					best = p
				}
			}
		}
		return best
	}
	if p := find(installedPackages()); p != "" {
		return p
	}
	refreshPackages()
	return find(installedPackages())
}

// launcherComponent mencari activity launcher utama sebuah package.
func launcherComponent(pkg string) string {
	out, _ := exec.Command("cmd", "package", "resolve-activity", "--brief",
		"-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", pkg).Output()
	comp := ""
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		l = strings.TrimSpace(l)
		if strings.Contains(l, "/") && !strings.Contains(l, " ") {
			comp = l
		}
	}
	return comp
}

// focused melaporkan apakah sebuah package sedang menjadi window fokus.
func focused(pkg string) bool {
	if pkg == "" {
		return false
	}
	out, _ := exec.Command("sh", "-c", "dumpsys window 2>/dev/null | grep mCurrentFocus").CombinedOutput()
	return strings.Contains(string(out), pkg)
}

func openApp(name string) (string, error) {
	defer noteAction("open_app")
	pkg := resolvePackage(name)
	if pkg == "" {
		return "", fmt.Errorf("aplikasi \"%s\" tidak ada/terpasang di HP ini", name)
	}
	// Cara utama: resolve komponen launcher lalu 'am start -W'. Output sistem
	// ("Status: ok" / "...brought to the front") menjadi acuan keberhasilan.
	if comp := launcherComponent(pkg); comp != "" {
		out, err := exec.Command("am", "start", "-W", "-n", comp).CombinedOutput()
		s := string(out)
		log.Printf("am start -W -n %s => err=%v out=%q", comp, err, strings.TrimSpace(s))
		if err == nil && strings.Contains(s, "Status: ok") &&
			!strings.Contains(s, "Error") && !strings.Contains(s, "does not exist") &&
			!strings.Contains(s, "not found") {
			log.Printf("openApp %s: dibawa ke depan (focused=%v)", pkg, focused(pkg))
			return fmt.Sprintf("Oke, %s sudah kubuka.", pkg), nil
		}
	}
	// Fallback: monkey.
	out, err := exec.Command("monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1").CombinedOutput()
	s := string(out)
	log.Printf("monkey -p %s => err=%v out=%q", pkg, err, strings.TrimSpace(s))
	if err == nil && !strings.Contains(s, "No activities found") && !strings.Contains(s, "aborted") && !strings.Contains(s, "Error") {
		return fmt.Sprintf("Oke, %s sudah kubuka.", pkg), nil
	}
	return "", fmt.Errorf("gagal buka %s: %s", pkg, strings.TrimSpace(s))
}

func openURL(u string) (string, error) {
	defer noteAction("open_url")
	u = strings.TrimSpace(u)
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	out, err := exec.Command("am", "start", "-a", "android.intent.action.VIEW", "-d", u).CombinedOutput()
	s := string(out)
	if err != nil || strings.Contains(s, "Error") || strings.Contains(s, "does not exist") {
		return "", fmt.Errorf("gagal buka URL %s: %s", u, strings.TrimSpace(s))
	}
	return fmt.Sprintf("Oke, aku buka %s sekarang.", u), nil
}

// commonDirs memetakan nama folder umum -> path absolut.
var commonDirs = map[string]string{
	"download":  "/storage/emulated/0/Download",
	"downloads": "/storage/emulated/0/Download",
	"unduhan":   "/storage/emulated/0/Download",
	"document":  "/storage/emulated/0/Documents",
	"documents": "/storage/emulated/0/Documents",
	"dokumen":   "/storage/emulated/0/Documents",
	"dcim":      "/storage/emulated/0/DCIM",
	"picture":   "/storage/emulated/0/Pictures",
	"pictures":  "/storage/emulated/0/Pictures",
	"gambar":    "/storage/emulated/0/Pictures",
	"photo":     "/storage/emulated/0/DCIM/Camera",
	"foto":      "/storage/emulated/0/DCIM/Camera",
	"music":     "/storage/emulated/0/Music",
	"musik":     "/storage/emulated/0/Music",
	"movie":     "/storage/emulated/0/Movies",
	"movies":    "/storage/emulated/0/Movies",
	"video":     "/storage/emulated/0/Movies",
	"android":   "/storage/emulated/0/Android",
	"whatsapp":  "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp",
	"telegram":  "/storage/emulated/0/Telegram",
}

var fileExtMime = map[string]string{
	"txt": "text/plain", "md": "text/plain", "log": "text/plain", "json": "application/json",
	"csv": "text/csv", "xml": "text/xml", "html": "text/html", "htm": "text/html",
	"pdf": "application/pdf",
	"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
	"webp": "image/webp", "bmp": "image/bmp", "svg": "image/svg+xml", "heic": "image/heic",
	"mp3": "audio/mpeg", "wav": "audio/x-wav", "m4a": "audio/mp4", "ogg": "audio/ogg",
	"flac": "audio/flac", "aac": "audio/aac",
	"mp4": "video/mp4", "mkv": "video/x-matroska", "avi": "video/x-msvideo",
	"webm": "video/webm", "3gp": "video/3gpp", "mov": "video/quicktime",
	"apk": "application/vnd.android.package-archive", "zip": "application/zip",
	"rar": "application/vnd.rar", "7z": "application/x-7z-compressed",
	"doc": "application/msword", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"xls": "application/vnd.ms-excel", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"ppt": "application/vnd.ms-powerpoint", "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

func fileExt(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if i := strings.LastIndex(base, "."); i >= 0 && i < len(base)-1 {
		return base[i+1:]
	}
	return ""
}

func hasFileExt(s string) bool {
	e := fileExt(s)
	if e == "" || len(e) > 5 {
		return false
	}
	_, ok := fileExtMime[e]
	return ok
}

func mimeFor(path string) string {
	if m, ok := fileExtMime[fileExt(path)]; ok {
		return m
	}
	return "*/*"
}

// expandPath mengubah nama pendek (mis. "Download", "catatan.txt") menjadi path absolut.
func expandPath(p string) string {
	p = strings.TrimSpace(strings.Trim(p, "\"'"))
	if p == "" {
		return p
	}
	if strings.HasPrefix(p, "~/") {
		p = "/storage/emulated/0/" + p[2:]
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if abs, ok := commonDirs[strings.ToLower(strings.TrimSuffix(p, "/"))]; ok {
		return abs
	}
	for _, dir := range []string{"/storage/emulated/0", "/storage/emulated/0/Download", "/storage/emulated/0/Documents", "/storage/emulated/0/Pictures", "/storage/emulated/0/DCIM", "/storage/emulated/0/Music", "/storage/emulated/0/Movies"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			return filepath.Join(dir, p)
		}
	}
	return "/storage/emulated/0/" + p
}

// looksLikePath menebak apakah argumen merujuk ke file/folder (bukan aplikasi).
func looksLikePath(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	if l == "" {
		return false
	}
	if strings.HasPrefix(l, "/") || strings.HasPrefix(l, "~/") || strings.Contains(l, "/") {
		return true
	}
	if hasFileExt(l) {
		return true
	}
	if _, ok := commonDirs[l]; ok {
		return true
	}
	for _, kw := range []string{"folder", "file", "direktori", "galeri", "gallery"} {
		if strings.HasPrefix(l, kw+" ") {
			return true
		}
	}
	return false
}

// openPath membuka file/folder dengan aplikasi penampil/pengelola bawaan.
func openPath(path string) (string, error) {
	defer noteAction("open_path")
	p := expandPath(path)
	if p == "" {
		return "", fmt.Errorf("path kosong")
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("tidak ditemukan: %s", p)
	}
	if fi.IsDir() {
		out, e := exec.Command("am", "start", "-a", "android.intent.action.VIEW",
			"-d", "file://"+p, "-t", "resource/folder").CombinedOutput()
		s := string(out)
		log.Printf("openPath dir %s => err=%v out=%q", p, e, strings.TrimSpace(s))
		if e == nil && !strings.Contains(s, "Error") && !strings.Contains(s, "does not exist") {
			return "Oke, folder dibuka: " + p, nil
		}
		return listDir(p)
	}
	mime := mimeFor(p)
	out, e := exec.Command("am", "start", "-a", "android.intent.action.VIEW",
		"-d", "file://"+p, "-t", mime).CombinedOutput()
	s := string(out)
	log.Printf("openPath file %s mime=%s => err=%v out=%q", p, mime, e, strings.TrimSpace(s))
	if e != nil || strings.Contains(s, "Error") || strings.Contains(s, "does not exist") {
		return "", fmt.Errorf("gagal membuka %s: %s", p, strings.TrimSpace(s))
	}
	return "Oke, file dibuka: " + p, nil
}

func webSearch(q string) (string, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", fmt.Errorf("kata kunci kosong")
	}
	return openURL("https://www.google.com/search?q=" + strings.ReplaceAll(q, " ", "+"))
}

func shellAllowed() bool {
	return cfg.AllowShell == nil || *cfg.AllowShell
}

func runShell(cmd string) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", fmt.Errorf("perintah kosong")
	}
	if !shellAllowed() {
		return "", fmt.Errorf("akses shell dimatikan (set \"allow_shell\": true di config.json)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	out, err := c.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if len(s) > 4000 {
		s = s[:4000] + "\n…(output dipotong)"
	}
	if ctx.Err() == context.DeadlineExceeded {
		if s == "" {
			s = "tidak ada output"
		}
		return s + "\n(timeout 60s)", nil
	}
	if err != nil && s == "" {
		return "", fmt.Errorf("gagal: %v", err)
	}
	if s == "" {
		s = "(perintah selesai, tanpa output)"
	}
	return s, nil
}

// ==================== UI automation ====================
//
// This group lets the agent actually see and operate the screen instead of
// only launching apps. Built entirely on Android's own uiautomator / input /
// screencap — no third-party dependencies.
//
// Design trade-offs:
//   - Prefer the uiautomator UI tree over screenshots: an order of magnitude
//     cheaper in tokens, and it yields tap coordinates directly so the model
//     never has to guess a position from an image.
//   - Every coordinate is the center of the node bounds, so the model can copy
//     it verbatim, which keeps taps from drifting.

const uiDumpPath = "/data/local/tmp/.agentd_ui.xml"

type uiNodeXML struct {
	Text       string      `xml:"text,attr"`
	Desc       string      `xml:"content-desc,attr"`
	Class      string      `xml:"class,attr"`
	Package    string      `xml:"package,attr"`
	Clickable  string      `xml:"clickable,attr"`
	Scrollable string      `xml:"scrollable,attr"`
	Enabled    string      `xml:"enabled,attr"`
	Bounds     string      `xml:"bounds,attr"`
	Nodes      []uiNodeXML `xml:"node"`
}

// parseBounds parses uiautomator's "[x1,y1][x2,y2]" bounds string.
// Returns zeros and false on a partial parse so callers never act on half a rect.
func parseBounds(s string) (x1, y1, x2, y2 int, ok bool) {
	var a, b, c, d int
	n, err := fmt.Sscanf(s, "[%d,%d][%d,%d]", &a, &b, &c, &d)
	if err != nil || n != 4 {
		return 0, 0, 0, 0, false
	}
	return a, b, c, d, true
}

// currentWindow returns the focused window. Informational only; empty on failure.
func currentWindow() string {
	out, err := exec.Command("sh", "-c",
		"dumpsys window 2>/dev/null | grep -E 'mCurrentFocus|mFocusedApp' | head -2").CombinedOutput()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// uiDumpXML dumps the UI hierarchy. Prefers --compressed (~60% smaller in
// testing) and falls back to a plain dump when unsupported.
func uiDumpXML() ([]byte, error) {
	_ = exec.Command("sh", "-c", "rm -f "+uiDumpPath).Run()

	try := func(flagArg string) bool {
		_ = exec.Command("sh", "-c",
			"uiautomator dump "+flagArg+" "+uiDumpPath+" >/dev/null 2>&1").Run()
		st, err := os.Stat(uiDumpPath)
		return err == nil && st.Size() > 0
	}
	if !try("--compressed") && !try("") {
		return nil, fmt.Errorf("uiautomator dump failed: screen may be FLAG_SECURE, or automation is restricted")
	}
	data, err := os.ReadFile(uiDumpPath)
	_ = os.Remove(uiDumpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dump result: %v", err)
	}
	return data, nil
}

// parseUILines flattens the uiautomator XML into "label @center" lines.
// Extracted from screenTool so it can be unit-tested without a device.
func parseUILines(data []byte) ([]string, error) {
	var root uiNodeXML
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse UI XML: %v", err)
	}

	var lines []string
	var walk func(n uiNodeXML, depth int)
	walk = func(n uiNodeXML, depth int) {
		label := strings.TrimSpace(n.Text)
		if label == "" {
			label = strings.TrimSpace(n.Desc)
		}
		if label != "" && depth < 48 {
			if x1, y1, x2, y2, ok := parseBounds(n.Bounds); ok {
				cls := n.Class
				if i := strings.LastIndex(cls, "."); i >= 0 {
					cls = cls[i+1:]
				}
				var flags []string
				if n.Clickable == "true" {
					flags = append(flags, "clickable")
				}
				if n.Scrollable == "true" {
					flags = append(flags, "scrollable")
				}
				if n.Enabled == "false" {
					flags = append(flags, "disabled")
				}
				label = strings.ReplaceAll(strings.ReplaceAll(label, "\n", " "), "\r", "")
				lines = append(lines, fmt.Sprintf("[%d] %s @(%d,%d) %s %s",
					len(lines)+1, truncate(label, 60), (x1+x2)/2, (y1+y2)/2,
					cls, strings.Join(flags, " ")))
			}
		}
		for _, c := range n.Nodes {
			walk(c, depth+1)
		}
	}
	walk(root, 0)
	return lines, nil
}

// screenTool returns a compact view of the screen: one line per labelled node,
// with its center coordinate.
func screenTool() (string, error) {
	data, err := uiDumpXML()
	if err != nil {
		return "", err
	}
	lines, err := parseUILines(data)
	if err != nil {
		return "", err
	}

	win := currentWindow()
	head := ""
	if win != "" {
		head = "Current window: " + win + "\n\n"
	}
	if len(lines) == 0 {
		return head + "(no labelled nodes found: FLAG_SECURE screen or pure graphics)", nil
	}
	if len(lines) > 90 {
		total := len(lines)
		lines = append(lines[:90], fmt.Sprintf("...and %d more nodes", total-90))
	}
	return head + strings.Join(lines, "\n"), nil
}

func tapTool(x, y, durMs int) (string, error) {
	if x < 0 || y < 0 || x > 20000 || y > 20000 {
		return "", fmt.Errorf("invalid coordinates: (%d,%d)", x, y)
	}
	var cmd string
	if durMs >= 400 {
		cmd = fmt.Sprintf("input swipe %d %d %d %d %d", x, y, x, y, durMs)
	} else {
		cmd = fmt.Sprintf("input tap %d %d", x, y)
	}
	if out, err := exec.Command("sh", "-c", cmd).CombinedOutput(); err != nil {
		return "", fmt.Errorf("tap failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if durMs >= 400 {
		return fmt.Sprintf("long-pressed (%d,%d) for %dms", x, y, durMs), nil
	}
	return fmt.Sprintf("tapped (%d,%d)", x, y), nil
}

func swipeTool(x1, y1, x2, y2, durMs int) (string, error) {
	if durMs <= 0 {
		durMs = 300
	}
	cmd := fmt.Sprintf("input swipe %d %d %d %d %d", x1, y1, x2, y2, durMs)
	if out, err := exec.Command("sh", "-c", cmd).CombinedOutput(); err != nil {
		return "", fmt.Errorf("swipe failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("swiped (%d,%d) -> (%d,%d) in %dms", x1, y1, x2, y2, durMs), nil
}

var keyNames = map[string]string{
	"HOME": "3", "BACK": "4", "ENTER": "66", "POWER": "26", "TAB": "61",
	"DEL": "67", "BACKSPACE": "67", "MENU": "82", "SEARCH": "84",
	"RECENT": "187", "APP_SWITCH": "187", "SPACE": "62", "CAMERA": "27",
	"WAKEUP": "224", "SLEEP": "223", "MUTE": "164", "PLAYPAUSE": "85",
	"VOLUP": "24", "VOLDOWN": "25", "UP": "19", "DOWN": "20",
	"LEFT": "21", "RIGHT": "22", "CENTER": "23",
}

func keyTool(k string) (string, error) {
	k = strings.TrimSpace(k)
	if k == "" {
		return "", fmt.Errorf("missing key name")
	}
	code := k
	if v, ok := keyNames[strings.ToUpper(k)]; ok {
		code = v
	}
	// Accept digits only: never splice model output into a shell command.
	if _, err := strconv.Atoi(code); err != nil {
		return "", fmt.Errorf("unknown key: %s (use HOME/BACK/ENTER/POWER/TAB or a numeric keycode)", k)
	}
	if out, err := exec.Command("sh", "-c", "input keyevent "+code).CombinedOutput(); err != nil {
		return "", fmt.Errorf("key event failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return "pressed " + strings.ToUpper(k) + " (" + code + ")", nil
}

var (
	adbKbOnce sync.Once
	adbKbOK   bool
)

// hasADBKeyboard reports whether ADBKeyboard is installed (an IME that can
// reliably inject arbitrary UTF-8).
func hasADBKeyboard() bool {
	adbKbOnce.Do(func() {
		out, _ := exec.Command("sh", "-c",
			"pm list packages 2>/dev/null | grep -q com.android.adbkeyboard && echo yes").CombinedOutput()
		adbKbOK = strings.TrimSpace(string(out)) == "yes"
	})
	return adbKbOK
}

// textTool types into the focused field.
//
// Non-ASCII is the long-standing problem: Android's `input text` only handles
// ASCII reliably. Two-stage fallback: ADBKeyboard broadcast (most reliable),
// then plain input text, and an explicit hint when the text may not appear.
func textTool(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("text is empty")
	}
	ascii := true
	for _, r := range s {
		if r < 32 || r > 126 {
			ascii = false
			break
		}
	}

	if hasADBKeyboard() {
		q := strings.ReplaceAll(s, `"`, `\"`)
		cmd := `am broadcast -a ADB_INPUT_TEXT --es msg "` + q + `"`
		if out, err := exec.Command("sh", "-c", cmd).CombinedOutput(); err == nil {
			_ = out
			return "typed (ADBKeyboard broadcast)", nil
		}
	}

	// Escape for a single-quoted shell string: ' -> '\''
	q := strings.ReplaceAll(s, "'", `'\''`)
	out, err := exec.Command("sh", "-c", "input text '"+q+"'").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("input failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if !ascii {
		return "attempted to type non-ASCII text. input text has limited support for it; " +
			"if nothing appeared in the field, install ADBKeyboard and retry.", nil
	}
	return "typed", nil
}

func screenshotTool(savePath string) (string, error) {
	if strings.TrimSpace(savePath) == "" {
		savePath = "/storage/emulated/0/Download/shot_" +
			time.Now().Format("20060102_150405") + ".png"
	}
	savePath = expandPath(savePath)

	tmp := "/data/local/tmp/.agentd_shot.png"
	_ = exec.Command("sh", "-c", "rm -f "+tmp).Run()
	if out, err := exec.Command("sh", "-c", "screencap -p "+tmp).CombinedOutput(); err != nil {
		return "", fmt.Errorf("screencap failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	st, err := os.Stat(tmp)
	if err != nil || st.Size() == 0 {
		return "", fmt.Errorf("screencap produced no file (screen may be FLAG_SECURE)")
	}
	if out, err := exec.Command("sh", "-c",
		"cp "+tmp+" "+shellQuote(savePath)+" && chmod 0666 "+shellQuote(savePath)).CombinedOutput(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("failed to save to %s: %v (%s)", savePath, err, strings.TrimSpace(string(out)))
	}
	_ = os.Remove(tmp)
	return fmt.Sprintf("screenshot saved: %s (%d KB)", savePath, st.Size()/1024), nil
}

func resultOrErr(msg string, err error) string {
	if err != nil {
		return err.Error()
	}
	return msg
}

func argStr(args map[string]interface{}, k string) string {
	if v, ok := args[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func toolStatus(name string, args map[string]interface{}) string {
	switch name {
	case "open_app":
		if a := argStr(args, "app"); a != "" {
			return "Membuka " + a + "..."
		}
		return "Membuka aplikasi..."
	case "open_url":
		return "Membuka tautan..."
	case "web_search":
		if q := argStr(args, "query"); q != "" {
			return "Mencari \"" + q + "\"..."
		}
		return "Mencari di Google..."
	case "run_shell":
		return "Menjalankan perintah..."
	case "write_file":
		return "Menulis file..."
	case "read_file":
		return "Membaca file..."
	case "list_dir":
		return "Melihat isi folder..."
	case "make_dir":
		return "Membuat folder..."
	case "move_file":
		return "Memindahkan/mengganti nama..."
	case "delete_path":
		return "Menghapus..."
	case "download_url":
		return "Mengunduh file..."
	case "open_path":
		if p := argStr(args, "path"); p != "" {
			return "Membuka " + p + "..."
		}
		return "Membuka file/folder..."
	case "schedule_message":
		if d := int(numArg(args, "delay_seconds")); d > 0 {
			return fmt.Sprintf("Menjadwalkan pengingat (%d detik)...", d)
		}
		return "Menjadwalkan pengingat..."
	// ---- UI automation ----
	case "screen":
		return "Membaca layar..."
	case "tap":
		if x, y := int(numArg(args, "x")), int(numArg(args, "y")); x > 0 || y > 0 {
			return fmt.Sprintf("Mengetuk (%d,%d)...", x, y)
		}
		return "Mengetuk layar..."
	case "swipe":
		return "Menggeser layar..."
	case "key":
		if k := argStr(args, "key"); k != "" {
			return "Menekan tombol " + strings.ToUpper(k) + "..."
		}
		return "Menekan tombol..."
	case "text":
		if t := argStr(args, "text"); t != "" {
			return "Mengetik \"" + truncate(t, 20) + "\"..."
		}
		return "Mengetik..."
	case "screenshot":
		return "Mengambil tangkapan layar..."
	}
	return ""
}

// execTool menjalankan satu aksi tool dan mengembalikan hasil (atau pesan error).
// execTool menjalankan satu aksi tool sambil memancarkan event 'tool' (mulai + hasil).
func execTool(name string, args map[string]interface{}) string {
	noteAction(name)
	id := nextToolID()
	label := toolStatus(name, args)
	if label == "" {
		label = name
	}
	broadcast(event{Type: "tool", ID: id, Name: name, Label: label, State: "start"})
	out := execToolInner(name, args)
	broadcast(event{Type: "tool", ID: id, Name: name, Label: label, Result: truncate(out, 500), State: "done"})
	return out
}

func execToolInner(name string, args map[string]interface{}) string {
	str := func(k string) string {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	switch name {
	case "open_app":
		log.Printf("[tool] open_app app=%q", str("app"))
		return resultOrErr(openApp(str("app")))
	case "open_url":
		log.Printf("[tool] open_url url=%q", str("url"))
		return resultOrErr(openURL(str("url")))
	case "web_search":
		q := str("query")
		if q == "" {
			q = str("q")
		}
		log.Printf("[tool] web_search q=%q", q)
		return resultOrErr(webSearch(q))
	case "run_shell":
		log.Printf("[tool] run_shell cmd=%q", str("command"))
		return resultOrErr(runShell(str("command")))
	case "write_file":
		return resultOrErr(writeFile(str("path"), str("content")))
	case "read_file":
		return resultOrErr(readFile(str("path")))
	case "list_dir":
		return resultOrErr(listDir(str("path")))
	case "make_dir":
		return resultOrErr(makeDir(str("path")))
	case "move_file":
		return resultOrErr(moveFile(str("from"), str("to")))
	case "delete_path":
		return resultOrErr(deletePath(str("path")))
	case "download_url":
		return resultOrErr(downloadURL(str("url"), str("path")))
	case "open_path":
		log.Printf("[tool] open_path path=%q", str("path"))
		return resultOrErr(openPath(str("path")))
	case "schedule_message":
		delay := int(numArg(args, "delay_seconds"))
		msg := str("message")
		log.Printf("[tool] schedule_message delay=%ds msg=%q", delay, msg)
		return scheduleMessage(delay, msg)
	case "screen":
		log.Printf("[tool] screen")
		return resultOrErr(screenTool())
	case "tap":
		x, y := int(numArg(args, "x")), int(numArg(args, "y"))
		log.Printf("[tool] tap (%d,%d)", x, y)
		return resultOrErr(tapTool(x, y, int(numArg(args, "duration_ms"))))
	case "swipe":
		log.Printf("[tool] swipe")
		return resultOrErr(swipeTool(
			int(numArg(args, "x1")), int(numArg(args, "y1")),
			int(numArg(args, "x2")), int(numArg(args, "y2")),
			int(numArg(args, "duration_ms"))))
	case "key":
		log.Printf("[tool] key %q", str("key"))
		return resultOrErr(keyTool(str("key")))
	case "text":
		log.Printf("[tool] text %q", truncate(str("text"), 40))
		return resultOrErr(textTool(str("text")))
	case "screenshot":
		log.Printf("[tool] screenshot")
		return resultOrErr(screenshotTool(str("path")))
	default:
		return "aksi tidak dikenal: " + name
	}
}

func numArg(args map[string]interface{}, k string) float64 {
	if v, ok := args[k]; ok {
		switch x := v.(type) {
		case float64:
			return x
		case int:
			return float64(x)
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
				return f
			}
		}
	}
	return 0
}

// pushMessage mengirim pesan tak-diminta dari agent ke chat pengguna (proaktif).
func pushMessage(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	mu.Lock()
	hist = append(hist, Msg{Role: "assistant", Content: text})
	saveHistory()
	mu.Unlock()
	broadcast(event{Type: "message", Text: text})
	log.Printf("[push] %s", truncate(text, 200))
	go notify("ZafxyrAgent AI", truncate(text, 80), "http://"+fmt.Sprintf("127.0.0.1:%d", cfg.Port))
}

// scheduleMessage menjadwalkan pesan otomatis setelah delay detik.
func scheduleMessage(delaySec int, text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return "pesan kosong, dibatalkan"
	}
	if delaySec < 0 {
		delaySec = 0
	}
	if delaySec > 86400 {
		delaySec = 86400
	}
	go func() {
		time.Sleep(time.Duration(delaySec) * time.Second)
		pushMessage(text)
	}()
	if delaySec == 0 {
		return "pesan dikirim sekarang"
	}
	return fmt.Sprintf("pesan dijadwalkan dalam %d detik", delaySec)
}

// runCalls dipertahankan agar kompatibel dengan pemanggil lama.
func runCalls(calls []gemFn) string {
	var out []string
	for _, c := range calls {
		out = append(out, execTool(c.Name, c.Args))
	}
	return strings.Join(out, "\n")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func writeFile(path, content string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path kosong")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("gagal tulis %s: %v", path, err)
	}
	return fmt.Sprintf("File dibuat: %s (%d byte)", path, len(content)), nil
}

func readFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path kosong")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("gagal baca %s: %v", path, err)
	}
	s := string(b)
	if len(s) > 4000 {
		s = s[:4000] + "\n…(dipotong)"
	}
	return s, nil
}

func listDir(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/storage/emulated/0"
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return "", fmt.Errorf("gagal list %s: %v", path, err)
	}
	var b strings.Builder
	for _, e := range entries {
		kind := "-"
		var size int64
		if e.IsDir() {
			kind = "d"
		} else if info, ierr := e.Info(); ierr == nil {
			size = info.Size()
		}
		fmt.Fprintf(&b, "%s %10d %s\n", kind, size, e.Name())
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		s = "(kosong)"
	}
	return s, nil
}

func makeDir(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path kosong")
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", fmt.Errorf("gagal buat folder %s: %v", path, err)
	}
	return "Folder dibuat: " + path, nil
}

func moveFile(from, to string) (string, error) {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if from == "" || to == "" {
		return "", fmt.Errorf("path sumber/tujuan kosong")
	}
	if err := os.MkdirAll(filepath.Dir(to), 0755); err != nil {
		_ = err
	}
	if err := os.Rename(from, to); err == nil {
		return fmt.Sprintf("Dipindah: %s -> %s", from, to), nil
	}
	if out, err := exec.Command("sh", "-c", "mv -f -- "+shellQuote(from)+" "+shellQuote(to)).CombinedOutput(); err != nil {
		return "", fmt.Errorf("gagal pindah: %v %s", err, strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("Dipindah: %s -> %s", from, to), nil
}

func deletePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path kosong")
	}
	if err := os.RemoveAll(path); err != nil {
		return "", fmt.Errorf("gagal hapus %s: %v", path, err)
	}
	return "Dihapus: " + path, nil
}

func downloadURL(url, path string) (string, error) {
	url = strings.TrimSpace(url)
	path = strings.TrimSpace(path)
	if url == "" || path == "" {
		return "", fmt.Errorf("url/path kosong")
	}
	if !strings.Contains(url, "://") {
		url = "https://" + url
	}
	resp, err := httpClient(120 * time.Second).Get(url)
	if err != nil {
		return "", fmt.Errorf("gagal unduh: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("gagal unduh: HTTP %d", resp.StatusCode)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		os.MkdirAll(dir, 0755)
	}
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("gagal simpan %s: %v", path, err)
	}
	defer f.Close()
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return "", fmt.Errorf("gagal tulis %s: %v", path, err)
	}
	return fmt.Sprintf("Terunduh: %s (%d byte)", path, n), nil
}

// slashCommand menangani perintah deterministik (/open, /url, /search) tanpa LLM.
func slashCommand(text string) (string, bool) {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "/") {
		if strings.HasPrefix(t, "$ ") {
			if msg, err := runShell(t[2:]); err != nil {
				return err.Error(), true
			} else {
				return msg, true
			}
		}
		return "", false
	}
	fields := strings.SplitN(t, " ", 2)
	cmd := strings.ToLower(fields[0])
	arg := ""
	if len(fields) > 1 {
		arg = strings.TrimSpace(fields[1])
	}
	switch cmd {
	case "/open", "/buka", "/launch", "/app":
		if arg == "" {
			return "Format: /open <nama app>  contoh: /open WhatsApp", true
		}
		if msg, err := openApp(arg); err != nil {
			return err.Error(), true
		} else {
			return msg, true
		}
	case "/url", "/link":
		if arg == "" {
			return "Format: /url <tautan>  contoh: /url example.com", true
		}
		if msg, err := openURL(arg); err != nil {
			return err.Error(), true
		} else {
			return msg, true
		}
	case "/search", "/cari", "/google":
		if arg == "" {
			return "Format: /search <kata kunci>", true
		}
		if msg, err := webSearch(arg); err != nil {
			return err.Error(), true
		} else {
			return msg, true
		}
	case "/sh", "/shell", "/su":
		if arg == "" {
			return "Format: /sh <perintah>  contoh: /sh df -h", true
		}
		if msg, err := runShell(arg); err != nil {
			return err.Error(), true
		} else {
			return msg, true
		}
	}
	return "", false
}

// quickIntent menangani perintah imperatif singkat secara deterministik
// (buka app / buka tautan) supaya agent SELALU benar-benar bertindak,
// tanpa bergantung pada kecerdasan tool-calling model. Perintah majemuk
// (mengandung "lalu/dan/kemudian") atau yang menyangkut file dibiarkan
// ke jalur LLM agent.
// quickIntent menangani perintah imperatif singkat secara deterministik:
// buka app / buka URL / buka file atau folder. Untuk yang ambigu (maksud lain,
// perintah majemuk, atau nama yang tidak dikenal) dikembalikan ke LLM agent
// agar bisa berpikir pakai semua tool.
func quickIntent(text string) (string, bool) {
	t := strings.TrimSpace(text)
	low := strings.ToLower(t)
	for _, p := range []string{"tolong ", "coba ", "silakan ", "please ", "bisakah kamu ", "bisa kamu ", "can you ", "bantu "} {
		if strings.HasPrefix(low, p) {
			t = strings.TrimSpace(t[len(p):])
			low = strings.ToLower(t)
			break
		}
	}
	prefixes := []struct {
		p      string
		isPath bool
	}{
		{"buka aplikasi ", false}, {"open aplikasi ", false}, {"buka app ", false}, {"open app ", false},
		{"buka folder ", true}, {"open folder ", true}, {"buka direktori ", true}, {"open dir ", true},
		{"buka file ", true}, {"open file ", true}, {"buka berkas ", true},
		{"buka ", false}, {"open ", false}, {"launch ", false}, {"jalankan ", false}, {"start ", false}, {"masuk ke ", false},
	}
	for _, pf := range prefixes {
		if !strings.HasPrefix(low, pf.p) {
			continue
		}
		arg := strings.TrimSpace(t[len(pf.p):])
		arg = strings.Trim(strings.TrimSpace(arg), "\"'")
		if arg == "" {
			return "", false
		}
		la := strings.ToLower(arg)
		// Perintah majemuk -> biarkan LLM yang menangani langkah-langkahnya.
		for _, conj := range []string{" dan ", " lalu ", " terus ", " kemudian ", ", ", " setelah ", " sambil "} {
			if strings.Contains(la, conj) {
				return "", false
			}
		}
		// 1) File/folder bila eksplisit ("buka file X", "buka folder X")
		if pf.isPath {
			if msg, err := openPath(arg); err == nil {
				return msg, true
			}
			return "", false
		}
		// 2) URL / tautan
		if isURL(la) {
			msg, err := openURL(arg)
			if err != nil {
				return err.Error(), true
			}
			return msg, true
		}
		// 3) Aplikasi yang benar-benar terpasang (prioritas untuk nama app)
		if resolvePackage(arg) != "" {
			msg, err := openApp(arg)
			if err != nil {
				return err.Error(), true
			}
			return msg, true
		}
		// 4) Terlihat seperti file/folder (mis. "Download", "catatan.txt", "/storage/...")
		if looksLikePath(la) {
			if msg, err := openPath(arg); err == nil {
				return msg, true
			}
			return "", false
		}
		// 5) Tidak yakin -> serahkan ke LLM agent.
		return "", false
	}
	return "", false
}

// isURL menebak apakah sebuah string adalah tautan.
func isURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "www.") {
		return true
	}
	if s == "" || strings.Contains(s, " ") {
		return false
	}
	for _, tld := range []string{".com", ".net", ".org", ".id", ".co", ".io", ".me", ".app", ".dev", ".xyz", ".info", ".site", ".online", ".shop", ".edu", ".gov"} {
		if strings.Contains(s, tld) {
			return true
		}
	}
	return false
}

type oaToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaMessage struct {
	Content   string       `json:"content"`
	ToolCalls []oaToolCall `json:"tool_calls"`
}

func openAIStep(url string, reqBody map[string]interface{}) (oaMessage, int, string, error) {
	jb, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jb))
	if err != nil {
		return oaMessage{}, 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	resp, err := httpClient(120 * time.Second).Do(req)
	if err != nil {
		return oaMessage{}, 0, "", err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return oaMessage{}, resp.StatusCode, string(body), nil
	}
	var out struct {
		Choices []struct {
			Message oaMessage `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return oaMessage{}, resp.StatusCode, string(body), err
	}
	if len(out.Choices) == 0 {
		return oaMessage{}, resp.StatusCode, string(body), nil
	}
	return out.Choices[0].Message, resp.StatusCode, "", nil
}

// openAIStepStream memanggil chat/completions dengan streaming SSE dan
// memanggil onToken untuk setiap potongan teks. tool_calls digabung per-index.
func openAIStepStream(url string, reqBody map[string]interface{}, onToken func(string)) (oaMessage, int, string, error) {
	reqBody["stream"] = true
	jb, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jb))
	if err != nil {
		return oaMessage{}, 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	resp, err := httpClient(180 * time.Second).Do(req)
	if err != nil {
		return oaMessage{}, 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return oaMessage{}, resp.StatusCode, string(b), nil
	}
	reader := bufio.NewReader(resp.Body)
	var content strings.Builder
	type acc struct {
		id   string
		name string
		args string
	}
	calls := map[int]*acc{}
	order := []int{}
	for {
		line, rerr := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			if data == "[DONE]" {
				break
			}
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content   string `json:"content"`
						ToolCalls []struct {
							Index    int    `json:"index"`
							ID       string `json:"id"`
							Function struct {
								Name      string `json:"name"`
								Arguments string `json:"arguments"`
							} `json:"function"`
						} `json:"tool_calls"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if json.Unmarshal([]byte(data), &chunk) == nil && len(chunk.Choices) > 0 {
				d := chunk.Choices[0].Delta
				if d.Content != "" {
					content.WriteString(d.Content)
					if onToken != nil {
						onToken(d.Content)
					}
				}
				for _, tc := range d.ToolCalls {
					a, ok := calls[tc.Index]
					if !ok {
						a = &acc{}
						calls[tc.Index] = a
						order = append(order, tc.Index)
					}
					if tc.ID != "" {
						a.id = tc.ID
					}
					if tc.Function.Name != "" {
						a.name = tc.Function.Name
					}
					a.args += tc.Function.Arguments
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	msg := oaMessage{Content: content.String()}
	for _, idx := range order {
		a := calls[idx]
		tc := oaToolCall{ID: a.id}
		tc.Function.Name = a.name
		tc.Function.Arguments = a.args
		msg.ToolCalls = append(msg.ToolCalls, tc)
	}
	return msg, 200, "", nil
}

func openAIAgent(model string, msgs []Msg) (string, int, string, error) {
	conv := make([]map[string]interface{}, 0, len(msgs))
	for _, m := range msgs {
		conv = append(conv, map[string]interface{}{"role": m.Role, "content": m.Content})
	}
	tools := openAIToolDecls()
	force := looksLikeCommand(lastUserMsg(msgs))
	url := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	for step := 0; step < maxAgentSteps; step++ {
		reqBody := map[string]interface{}{"model": model, "messages": conv, "max_tokens": cfg.MaxTokens}
		forceNow := force && step == 0
		if len(tools) > 0 {
			reqBody["tools"] = tools
			if forceNow {
				reqBody["tool_choice"] = "required"
			} else {
				reqBody["tool_choice"] = "auto"
			}
		}
		var msg oaMessage
		var statusCode int
		var bodyStr string
		var lastErr error
		got := false
		for attempt := 0; attempt < 3; attempt++ {
			m, st, bs, err := openAIStepStream(url, reqBody, func(tok string) {
				broadcast(event{Type: "token", Text: tok})
			})
			if err != nil {
				lastErr = err
				time.Sleep(500 * time.Millisecond)
				continue
			}
			if st < 200 || st >= 300 {
				if forceNow {
					log.Printf("[model %s] tool_choice=required ditolak (%d), ulangi dengan auto", model, st)
					forceNow = false
					if len(tools) > 0 {
						reqBody["tool_choice"] = "auto"
					}
					continue
				}
				return "", st, bs, nil
			}
			statusCode, bodyStr = st, bs
			msg = m
			if len(msg.ToolCalls) > 0 || strings.TrimSpace(msg.Content) != "" {
				got = true
				break
			}
			log.Printf("[model %s] balasan kosong (percobaan %d), ulangi", model, attempt+1)
			time.Sleep(700 * time.Millisecond)
		}
		if lastErr != nil && !got {
			return "", 0, "", lastErr
		}
		if !got {
			return "", statusCode, bodyStr, nil
		}
		if len(msg.ToolCalls) == 0 {
			log.Printf("[model %s] text-only reply: %q", model, msg.Content)
			return msg.Content, statusCode, "", nil
		}
		log.Printf("[model %s] step %d: %d tool_calls", model, step, len(msg.ToolCalls))
		// Langkah agent: catat tool_call, jalankan, kirim hasilnya balik, ulangi.
		tcs := make([]map[string]interface{}, 0, len(msg.ToolCalls))
		for _, tc := range msg.ToolCalls {
			tcs = append(tcs, map[string]interface{}{
				"id":   tc.ID,
				"type": "function",
				"function": map[string]interface{}{
					"name":      tc.Function.Name,
					"arguments": tc.Function.Arguments,
				},
			})
		}
		assistant := map[string]interface{}{"role": "assistant", "tool_calls": tcs}
		if strings.TrimSpace(msg.Content) != "" {
			assistant["content"] = msg.Content
		}
		conv = append(conv, assistant)
		for _, tc := range msg.ToolCalls {
			var args map[string]interface{}
			if tc.Function.Arguments != "" {
				json.Unmarshal([]byte(tc.Function.Arguments), &args)
			}
			conv = append(conv, map[string]interface{}{
				"role":         "tool",
				"tool_call_id": tc.ID,
				"content":      execTool(tc.Function.Name, args),
			})
		}
	}
	return "Maaf, tugasnya butuh terlalu banyak langkah. Coba pecah jadi perintah yang lebih kecil.", 200, "", nil
}

func callOpenAI(msgs []Msg) (string, error) {
	models := []string{cfg.Model}
	for _, fb := range cfg.Fallback {
		if fb != "" && fb != cfg.Model {
			models = append(models, fb)
		}
	}
	var lastErr error
	for i, m := range models {
		text, status, body, err := openAIAgent(m, msgs)
		if err != nil {
			return "", err
		}
		if status >= 200 && status < 300 {
			if strings.TrimSpace(text) != "" {
				return text, nil
			}
			lastErr = fmt.Errorf("empty response: %s", body)
			continue
		}
		lastErr = fmt.Errorf("HTTP %d: %s", status, body)
		if (status == 402 || status == 429 || status == 404) && i < len(models)-1 {
			log.Printf("model %s gagal (%d), fallback ke %s", m, status, models[i+1])
			continue
		}
		break
	}
	return "", lastErr
}

// openAIToolDecls menerjemahkan tool agent ke format OpenAI/OpenRouter (tools[].function).
func openAIToolDecls() []interface{} {
	prop := func(t, desc string) map[string]interface{} {
		m := map[string]interface{}{"type": t}
		if desc != "" {
			m["description"] = desc
		}
		return m
	}
	add := func(name, desc string, props map[string]interface{}, required []string) map[string]interface{} {
		return map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name":        name,
				"description": desc,
				"parameters": map[string]interface{}{
					"type":       "object",
					"properties": props,
					"required":   required,
				},
			},
		}
	}
	funcs := []interface{}{
		add("open_app",
			"Buka (launch) sebuah aplikasi di HP pengguna berdasarkan namanya (mis. WhatsApp, YouTube, Instagram) atau nama package (mis. com.whatsapp).",
			map[string]interface{}{"app": prop("string", "nama aplikasi atau nama package")},
			[]string{"app"}),
		add("open_url",
			"Buka sebuah URL/tautan di browser HP pengguna. Tambahkan https:// bila tidak ada.",
			map[string]interface{}{"url": prop("string", "URL yang akan dibuka")},
			[]string{"url"}),
		add("web_search",
			"Cari sesuatu di Google dan buka hasil pencariannya di browser HP.",
			map[string]interface{}{"query": prop("string", "kata kunci pencarian")},
			[]string{"query"}),
	}
	if shellAllowed() {
		funcs = append(funcs, add("run_shell",
			"Jalankan perintah shell di HP pengguna (root) dan kembalikan output. "+
				"Pakai HANYA saat pengguna minta menjalankan perintah/shell, cek sistem, kelola file, atau tugas teknis. "+
				"Contoh: 'cek storage', 'list file Download', 'sisa baterai', 'pm list packages | grep wa'.",
			map[string]interface{}{"command": prop("string", "perintah shell yang dijalankan via sh -c")},
			[]string{"command"}))
	}
	funcs = append(funcs,
		add("write_file", "Tulis/buat file baru di HP (menimpa bila sudah ada); folder induk dibuat otomatis. Gunakan path absolut, mis. /storage/emulated/0/Download/note.txt.", map[string]interface{}{"path": prop("string", "path absolut file"), "content": prop("string", "isi file")}, []string{"path", "content"}),
		add("read_file", "Baca isi sebuah file teks di HP. Gunakan path absolut.", map[string]interface{}{"path": prop("string", "path absolut file")}, []string{"path"}),
		add("list_dir", "Tampilkan daftar file/folder pada sebuah direktori di HP.", map[string]interface{}{"path": prop("string", "path direktori, mis. /storage/emulated/0/Download")}, []string{"path"}),
		add("make_dir", "Buat folder (beserta folder induknya) di HP.", map[string]interface{}{"path": prop("string", "path folder")}, []string{"path"}),
		add("move_file", "Pindahkan atau ganti nama file/folder di HP.", map[string]interface{}{"from": prop("string", "path sumber"), "to": prop("string", "path tujuan")}, []string{"from", "to"}),
		add("delete_path", "Hapus file atau folder di HP.", map[string]interface{}{"path": prop("string", "path yang akan dihapus")}, []string{"path"}),
		add("download_url", "Unduh file dari internet lalu simpan ke path di HP.", map[string]interface{}{"url": prop("string", "URL file yang diunduh"), "path": prop("string", "path tujuan penyimpanan")}, []string{"url", "path"}),
		add("open_path", "Buka sebuah FILE atau FOLDER di HP dengan aplikasi penampil/pengelola bawaan. Pakai untuk permintaan seperti 'buka file catatan.txt', 'buka folder Download', 'buka foto/video/musik'. BUKAN untuk aplikasi; untuk aplikasi pakai open_app.", map[string]interface{}{"path": prop("string", "path absolut file atau folder")}, []string{"path"}),
		add("schedule_message", "Jadwalkan PESAN OTOMATIS dari agent ke pengguna setelah jeda waktu tertentu (pengingat/reminder). Agent mengirim pesan ini sendiri tanpa ditanya lagi. Pakai saat pengguna minta diingatkan sesuatu, mis. 'ingetin 10 menit lagi minum obat'.", map[string]interface{}{"delay_seconds": prop("integer", "jeda waktu dalam detik sebelum pesan dikirim"), "message": prop("string", "isi pesan pengingat yang akan dikirim nanti")}, []string{"delay_seconds", "message"}),
		// ---- UI automation: let the agent actually operate the screen, not just launch apps ----
		add("screen", "Read the current UI tree and return clickable nodes with their center coordinates. Prefer this over screenshots when you need to see the screen, find a button, or confirm the previous action took effect.", map[string]interface{}{}, []string{}),
		add("tap", "Tap screen coordinates. Coordinates must come from the @(x,y) values returned by screen; do not guess. duration_ms>=400 is treated as a long press.", map[string]interface{}{"x": prop("integer", "x coordinate"), "y": prop("integer", "y coordinate"), "duration_ms": prop("integer", "hold duration in ms, default 80; >=400 means long press")}, []string{"x", "y"}),
		add("swipe", "Swipe across the screen to scroll lists, change pages, or pull down the notification shade.", map[string]interface{}{"x1": prop("integer", "start x"), "y1": prop("integer", "start y"), "x2": prop("integer", "end x"), "y2": prop("integer", "end y"), "duration_ms": prop("integer", "swipe duration in ms, default 300")}, []string{"x1", "y1", "x2", "y2"}),
		add("key", "Send a key event such as back, home, enter, or delete.", map[string]interface{}{"key": prop("string", "HOME/BACK/ENTER/POWER/TAB/DEL/MENU/RECENT/VOLUP/VOLDOWN, or a numeric keycode")}, []string{"key"}),
		add("text", "Type text into the focused input field. Uses ADBKeyboard when available for full Unicode; otherwise falls back to input text, which is ASCII-only.", map[string]interface{}{"text": prop("string", "text to type")}, []string{"text"}),
		add("screenshot", "Capture the screen to a PNG file and return its path. Only use this when screen cannot describe the UI (pure graphics).", map[string]interface{}{"path": prop("string", "save path; defaults to /storage/emulated/0/Download")}, []string{}),
	)
	return funcs
}

func lastUserMsg(msgs []Msg) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return msgs[i].Content
		}
	}
	return ""
}

// looksLikeCommand menebak apakah pesan adalah perintah aksi (bukan sekadar obrolan).
func looksLikeCommand(text string) bool {
	s := strings.ToLower(strings.TrimSpace(text))
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "/") {
		return true
	}
	for _, v := range []string{
		"buka", "open", "launch", "jalankan", "run ", "eksekusi", "download", "unduh",
		"install", "pasang", "hapus", "delete", "buat", "bikin", "tulis", "write",
		"baca", "read", "list", "lihat", "tampilkan", "cek", "check", "pindah",
		"move", "rename", "ganti nama", "kirim", "cari", "search", "restart",
		"matikan", "hidupkan", "set ", "ubah", "edit", "copy", "salin", "unzip",
		"extract", "kompres", "zip", "screenshot", "rekam", "hubungi", "telpon",
		"ingatkan", "ingetin", "reminder", "alarm", "jadwalkan", "jadwal",
	} {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

// parseSuggestions memisahkan baris "SARAN: ..." dari balasan menjadi chip pilihan.
func parseSuggestions(reply string) (string, []string) {
	lines := strings.Split(reply, "\n")
	kept := make([]string, 0, len(lines))
	var sugg []string
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		up := strings.ToUpper(t)
		if strings.HasPrefix(up, "SARAN:") || strings.HasPrefix(up, "SARAN :") ||
			strings.HasPrefix(up, "SUGGEST:") || strings.HasPrefix(up, "SARAN-") {
			rest := t[strings.Index(t, ":")+1:]
			rest = strings.TrimPrefix(rest, "-")
			for _, part := range strings.Split(rest, "|") {
				p := strings.TrimSpace(strings.Trim(strings.TrimSpace(part), "\"'"))
				if p != "" {
					sugg = append(sugg, p)
				}
			}
			continue
		}
		kept = append(kept, ln)
	}
	clean := strings.TrimSpace(strings.Join(kept, "\n"))
	if len(sugg) > 4 {
		sugg = sugg[:4]
	}
	return clean, sugg
}

// defaultSuggestions menyusun chip cadangan berdasarkan aksi yang barusan dilakukan.
func defaultSuggestions(actions []string) []string {
	has := func(n string) bool {
		for _, a := range actions {
			if a == n {
				return true
			}
		}
		return false
	}
	switch {
	case has("download_url"):
		return []string{"Buka file hasil unduhan", "Lihat folder Download", "Cek sisa storage"}
	case has("open_app"):
		return []string{"Buka WhatsApp", "Cek sisa storage", "Lihat folder Download"}
	case has("open_path"), has("list_dir"):
		return []string{"Lihat isi folder", "Buka file lain", "Cek sisa storage"}
	case has("write_file"), has("make_dir"):
		return []string{"Baca file itu", "Lihat folder Download", "Cek sisa storage"}
	case has("run_shell"):
		return []string{"Jalankan perintah lain", "Cek sisa storage", "Lihat folder Download"}
	case has("web_search"):
		return []string{"Buka hasil pertama", "Cari hal lain", "Cek sisa storage"}
	case has("open_url"):
		return []string{"Cari hal lain", "Buka YouTube", "Cek sisa storage"}
	case has("schedule_message"):
		return []string{"Buat pengingat lain", "Buka aplikasi pengingat", "Cek sisa storage"}
	}
	return []string{"Cek sisa storage", "Lihat folder Download", "Buka WhatsApp"}
}

// fallbackAck memberi konfirmasi singkat saat model tidak menulis teks (hanya SARAN).
func fallbackAck(actions []string) string {
	for _, a := range actions {
		switch a {
		case "schedule_message":
			return "Siap, pengingat sudah dijadwalkan."
		case "open_app":
			return "Siap, sudah dibuka."
		case "open_url":
			return "Siap, sudah dibuka di browser."
		case "download_url":
			return "Siap, unduhan selesai."
		case "write_file":
			return "Siap, file sudah dibuat."
		case "delete_path":
			return "Siap, sudah dihapus."
		case "move_file":
			return "Siap, sudah dipindahkan."
		case "run_shell":
			return "Siap, perintah sudah dijalankan."
		}
	}
	return "Siap, sudah saya kerjakan."
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	msg := strings.TrimSpace(in.Message)
	if msg == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "pesan kosong"})
		return
	}
	mu.Lock()
	hist = append(hist, Msg{Role: "user", Content: msg})
	mu.Unlock()

	resetActions()

	var reply string
	var err error
	if r2, ok := slashCommand(msg); ok {
		reply = r2
	} else if r2, ok := quickIntent(msg); ok {
		log.Printf("[quickIntent] %q -> %q", msg, r2)
		reply = r2
	} else {
		status("Berpikir...")
		mu.Lock()
		msgs := make([]Msg, 0, len(hist)+1)
		msgs = append(msgs, Msg{Role: "system", Content: cfg.System})
		msgs = append(msgs, hist...)
		mu.Unlock()
		reply, err = callLLM(msgs)
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		mu.Lock()
		hist = hist[:len(hist)-1]
		mu.Unlock()
		broadcast(event{Type: "error", Text: err.Error()})
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	acts := snapshotActions()
	clean, sugg := parseSuggestions(reply)
	if strings.TrimSpace(clean) == "" {
		clean = fallbackAck(acts)
	}
	if len(sugg) == 0 {
		sugg = defaultSuggestions(acts)
	}

	mu.Lock()
	hist = append(hist, Msg{Role: "assistant", Content: clean})
	saveHistory()
	mu.Unlock()

	broadcast(event{Type: "reply", Text: clean, Suggestions: sugg})
	json.NewEncoder(w).Encode(map[string]interface{}{"reply": clean, "suggestions": sugg})
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	cur := cfg.Model
	list := append([]string(nil), cfg.Models...)
	mu.Unlock()
	if len(list) == 0 {
		list = []string{cur}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"current": cur, "models": list})
}

func handleSetModel(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Model string `json:"model"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	w.Header().Set("Content-Type", "application/json")
	if !setModel(in.Model) {
		json.NewEncoder(w).Encode(map[string]string{"error": "model kosong"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"model": in.Model})
}

func handleRandomModel(w http.ResponseWriter, r *http.Request) {
	m := randomModel()
	setModel(m)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"model": m})
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hist)
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	hist = nil
	saveHistory()
	mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
}

// handleConfig lets the user change settings from the chat UI instead of
// editing JSON with a root editor. GET never returns the api_key itself,
// only whether one is set.
func handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"provider":    cfg.Provider,
			"base_url":    cfg.BaseURL,
			"model":       cfg.Model,
			"max_tokens":  cfg.MaxTokens,
			"port":        cfg.Port,
			"has_key":     strings.TrimSpace(cfg.APIKey) != "",
			"allow_shell": shellAllowed(),
			"config_path": configPath(),
		})
	case http.MethodPost:
		var body struct {
			APIKey    string `json:"api_key"`
			BaseURL   string `json:"base_url"`
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"ok":false,"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		if v := strings.TrimSpace(body.APIKey); v != "" {
			cfg.APIKey = v
		}
		if v := strings.TrimSpace(body.BaseURL); v != "" {
			cfg.BaseURL = v
			// provider must match base_url or requests fail silently in the wrong
			// protocol. Google's endpoint is gemini; everything else is OpenAI-compatible
			// (DeepSeek / OpenRouter / local llama.cpp all are).
			if strings.Contains(v, "generativelanguage.googleapis.com") {
				cfg.Provider = "gemini"
			} else {
				cfg.Provider = "openai"
			}
		}
		if v := strings.TrimSpace(body.Model); v != "" {
			cfg.Model = v
			// Put the new model first in the picker list and de-duplicate, otherwise the
			// dropdown cannot select it (cfg.Model changed but the list came from cfg.Models).
			list := []string{v}
			for _, m := range cfg.Models {
				if m != v {
					list = append(list, m)
				}
			}
			cfg.Models = list
		}
		if body.MaxTokens > 0 {
			cfg.MaxTokens = body.MaxTokens
		}
		saveConfig()
		log.Printf("[config] updated via UI (key set=%v model=%q)", cfg.APIKey != "", cfg.Model)
		fmt.Fprint(w, `{"ok":true}`)
	default:
		http.Error(w, `{"ok":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func main() {
	defMod := ""
	if exe, err := os.Executable(); err == nil {
		defMod = filepath.Dir(filepath.Dir(exe))
	}
	flag.StringVar(&modDir, "moddir", defMod, "module directory")
	flag.StringVar(&home, "home", "/data/adb/aiagent", "data directory")
	flag.Parse()
	os.MkdirAll(home, 0700)

	log.Printf("aiagent starting moddir=%s home=%s", modDir, home)
	loadConfig()
	loadHistory()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/chat", handleChat)
	mux.HandleFunc("/models", handleModels)
	mux.HandleFunc("/model", handleSetModel)
	mux.HandleFunc("/model/random", handleRandomModel)
	mux.HandleFunc("/history", handleHistory)
	mux.HandleFunc("/reset", handleReset)
	mux.HandleFunc("/config", handleConfig)
	mux.HandleFunc("/events", handleEvents)

	// Debug endpoint, mounted only when AGENTD_DEBUG=1. Lets you exercise tools
	// (screen/tap/...) on a real device without a working LLM first. Absent by
	// default, so production behaviour is unchanged.
	if os.Getenv("AGENTD_DEBUG") == "1" {
		mux.HandleFunc("/debug/tool", func(w http.ResponseWriter, r *http.Request) {
			name := r.URL.Query().Get("name")
			if name == "" {
				http.Error(w, "missing name", http.StatusBadRequest)
				return
			}
			args := map[string]interface{}{}
			if raw := r.URL.Query().Get("args"); raw != "" {
				if err := json.Unmarshal([]byte(raw), &args); err != nil {
					http.Error(w, "bad args json: "+err.Error(), http.StatusBadRequest)
					return
				}
			}
			log.Printf("[debug] tool=%s args=%v", name, args)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprint(w, execToolInner(name, args))
		})
		log.Printf("debug endpoint enabled: /debug/tool")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	go func() {
		time.Sleep(2 * time.Second)
		notify("ZafxyrAgent AI", "Tap untuk buka chat", "http://"+addr)
	}()
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
