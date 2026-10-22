package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// Non-ASCII must be truncated by rune; cutting mid UTF-8 sequence yields mojibake.
// This was hit on device: screen output showed `"..." · �...`.
func TestTruncateUTF8(t *testing.T) {
	zh := strings.Repeat("中文测试", 30) // 120 runes
	got := truncate(zh, 60)
	if !utf8.ValidString(got) {
		t.Fatalf("truncated string is not valid UTF-8: %q", got)
	}
	if n := len([]rune(got)); n != 63 { // 60 runes + "..."
		t.Errorf("expected 60 runes + ellipsis (63), got %d", n)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected a trailing ellipsis: %q", got)
	}

	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short input must not be truncated, got %q", got)
	}
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("wrong ASCII truncation: %q", got)
	}
	if got := truncate("  hi  ", 10); got != "hi" {
		t.Errorf("expected trimmed output, got %q", got)
	}
}

func TestParseBounds(t *testing.T) {
	cases := []struct {
		in             string
		x1, y1, x2, y2 int
		ok             bool
	}{
		{"[0,0][1220,2712]", 0, 0, 1220, 2712, true},
		{"[60,180][240,260]", 60, 180, 240, 260, true},
		{"[80,300][1000,400]", 80, 300, 1000, 400, true},
		{"", 0, 0, 0, 0, false},
		{"garbage", 0, 0, 0, 0, false},
		{"[1,2][3]", 0, 0, 0, 0, false},
	}
	for _, c := range cases {
		x1, y1, x2, y2, ok := parseBounds(c.in)
		if ok != c.ok || x1 != c.x1 || y1 != c.y1 || x2 != c.x2 || y2 != c.y2 {
			t.Errorf("parseBounds(%q) = %d,%d,%d,%d,%v; want %d,%d,%d,%d,%v",
				c.in, x1, y1, x2, y2, ok, c.x1, c.y1, c.x2, c.y2, c.ok)
		}
	}
}

// Structure copied from a real dump on a Redmi 2407FRK8EC / Android 16.
const sampleXML = `<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0"><node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.tencent.mm" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,0][1220,2712]" drawing-order="0" hint=""><node index="1" text="微信" resource-id="com.tencent.mm:id/title" class="android.widget.TextView" package="com.tencent.mm" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[60,180][240,260]" drawing-order="1" hint="" /><node index="2" text="" resource-id="com.tencent.mm:id/search" class="android.widget.EditText" package="com.tencent.mm" content-desc="搜索" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[80,300][1000,400]" drawing-order="2" hint="搜索" /><node index="3" text="聊天记录" resource-id="" class="android.widget.Button" package="com.tencent.mm" content-desc="" checkable="false" checked="false" clickable="true" enabled="false" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,500][1220,600]" drawing-order="3" hint="" /></node></hierarchy>`

func TestParseUILines(t *testing.T) {
	lines, err := parseUILines([]byte(sampleXML))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(lines), lines)
	}
	// #1 uses the text attribute; center = (60+240)/2=150, (180+260)/2=220
	if !strings.Contains(lines[0], "微信") || !strings.Contains(lines[0], "@(150,220)") {
		t.Errorf("line 1 wrong: %q", lines[0])
	}
	// #2 has empty text, so it falls back to content-desc; also marked clickable
	if !strings.Contains(lines[1], "搜索") || !strings.Contains(lines[1], "clickable") {
		t.Errorf("line 2 wrong: %q", lines[1])
	}
	if !strings.Contains(lines[1], "@(540,350)") {
		t.Errorf("line 2 coordinates wrong: %q", lines[1])
	}
	// #3 has enabled=false, so it is marked disabled
	if !strings.Contains(lines[2], "disabled") {
		t.Errorf("line 3 should be marked disabled: %q", lines[2])
	}
}

func TestParseUILinesEmpty(t *testing.T) {
	lines, err := parseUILines([]byte(`<hierarchy></hierarchy>`))
	if err != nil {
		t.Fatalf("empty tree must not error: %v", err)
	}
	if len(lines) != 0 {
		t.Errorf("expected 0 lines, got %v", lines)
	}
}

func TestParseUILinesMalformed(t *testing.T) {
	if _, err := parseUILines([]byte(`<hierarchy><node text="x"`)); err == nil {
		t.Error("malformed XML should error")
	}
}

// keyTool splices its argument into a shell command, so injection must be
// blocked before anything runs.
func TestKeyToolRejectsInjection(t *testing.T) {
	bad := []string{
		"3; rm -rf /",
		"HOME && reboot",
		"$(id)",
		"`id`",
		"3|ls",
		"abc",
		"",
		"HOME;touch /tmp/pwned",
	}
	for _, b := range bad {
		if got, err := keyTool(b); err == nil {
			t.Errorf("keyTool(%q) should be rejected, returned %q", b, got)
		}
	}
}

func TestTapToolRejectsBadCoords(t *testing.T) {
	if _, err := tapTool(-1, 10, 0); err == nil {
		t.Error("negative coordinates should be rejected")
	}
	if _, err := tapTool(10, 999999, 0); err == nil {
		t.Error("out-of-range coordinates should be rejected")
	}
}

func TestKeyNamesCoverage(t *testing.T) {
	for _, k := range []string{"HOME", "BACK", "ENTER", "POWER", "TAB", "DEL", "MENU", "RECENT"} {
		if _, ok := keyNames[k]; !ok {
			t.Errorf("keyNames is missing common key %s", k)
		}
	}
}

// Config lookup order and the defaults used when no config exists.
// Both were buggy: a missing config returned early and left Port=0 (server bound
// to a random port), and the config lived only in the module dir, so flashing an
// update overwrote it and the path disagreed with the README.
func TestConfigPathPriority(t *testing.T) {
	dir := t.TempDir()
	oldHome, oldMod, oldCfg := home, modDir, cfg
	defer func() { home, modDir, cfg = oldHome, oldMod, oldCfg }()

	home = filepath.Join(dir, "home")
	modDir = filepath.Join(dir, "mod")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(modDir, 0700); err != nil {
		t.Fatal(err)
	}
	modConf := filepath.Join(modDir, "config.json")

	// 1) only the factory template in the module dir -> fall back to it
	if err := os.WriteFile(modConf, []byte(`{"port":1234,"model":"from-mod"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg = Config{}
	loadConfig()
	if cfg.Port != 1234 || cfg.Model != "from-mod" {
		t.Errorf("should fall back to the module config, got port=%d model=%q", cfg.Port, cfg.Model)
	}

	// 2) home also has one -> home wins, so module updates keep user settings
	if err := os.WriteFile(configPath(), []byte(`{"port":4321,"model":"from-home"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg = Config{}
	loadConfig()
	if cfg.Port != 4321 || cfg.Model != "from-home" {
		t.Errorf("home config should win, got port=%d model=%q", cfg.Port, cfg.Model)
	}

	// 3) neither exists -> defaults must apply
	_ = os.Remove(configPath())
	_ = os.Remove(modConf)
	cfg = Config{}
	loadConfig()
	if cfg.Port != 8787 {
		t.Errorf("missing config should fall back to port 8787, got %d", cfg.Port)
	}
	if cfg.Model == "" || cfg.BaseURL == "" {
		t.Errorf("incomplete defaults when config is missing: model=%q baseURL=%q", cfg.Model, cfg.BaseURL)
	}
}
