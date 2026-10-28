package guictrl

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kshishtovsky/rupas/internal/update"
	"github.com/kshishtovsky/rupas/internal/version"
)

// updateThrottle keeps the background check to twice a day.
const updateThrottle = 12 * time.Hour

// UpdateInfo is what the GUI renders after a version check.
type UpdateInfo struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest"`
	Available bool      `json:"available"`
	Notes     string    `json:"notes"`
	URL       string    `json:"url"`
	CheckedAt time.Time `json:"checkedAt"`
}

// updateState is the persisted result — the throttle and the ETag live here so
// a restart does not re-ask GitHub.
type updateState struct {
	CheckedAt time.Time `json:"checkedAt"`
	ETag      string    `json:"etag"`
	Latest    string    `json:"latest"`
	Notes     string    `json:"notes"`
	URL       string    `json:"url"`
}

func updateStatePath() string {
	dir := os.Getenv("LocalAppData")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "rupas", "update.json")
}

func loadUpdateState() updateState {
	var st updateState
	b, err := os.ReadFile(updateStatePath())
	if err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func saveUpdateState(st updateState) {
	p := updateStatePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	if b, err := json.Marshal(st); err == nil {
		_ = os.WriteFile(p, b, 0o600)
	}
}

// CheckUpdate asks GitHub for the latest release and answers whether it is
// newer than this build. force=true ignores the 12h throttle (manual button,
// but not faster than once a minute).
func (c *Controller) CheckUpdate(force bool) (UpdateInfo, error) {
	cur := version.Version
	st := loadUpdateState()
	now := time.Now()

	if force && now.Sub(st.CheckedAt) < time.Minute {
		return knownUpdate(st, cur), nil // anti-double-click, keep the last answer
	}
	if !force && now.Sub(st.CheckedAt) < updateThrottle {
		return knownUpdate(st, cur), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := &update.Client{ETag: st.ETag}
	rel, err := client.Latest(ctx)
	if errors.Is(err, update.ErrNotModified) {
		st.CheckedAt = now
		st.ETag = client.ETag
		saveUpdateState(st)
		return knownUpdate(st, cur), nil
	}
	if err != nil {
		return UpdateInfo{Current: cur}, err
	}

	st = updateState{CheckedAt: now, ETag: client.ETag, Latest: rel.TagName, Notes: rel.Body, URL: rel.HTMLURL}
	saveUpdateState(st)
	return knownUpdate(st, cur), nil
}

func knownUpdate(st updateState, cur string) UpdateInfo {
	return UpdateInfo{
		Current:   cur,
		Latest:    st.Latest,
		Available: version.Newer(st.Latest, cur),
		Notes:     st.Notes,
		URL:       st.URL,
		CheckedAt: st.CheckedAt,
	}
}

// DownloadUpdate fetches the Windows archive into
// %LocalAppData%\rupas\updates\<ver>, verifies it against the release's
// SHA256SUMS.txt and unpacks it. Returns "Готово" + the folder when the files
// are on disk and safe to swap in.
//
// shortcut: the swap itself is done by updater.cmd on exit — it cannot be
// verified without a real install dir, so the GUI walks the user through it.
func (c *Controller) DownloadUpdate() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := &update.Client{}
	rel, err := client.Latest(ctx)
	if err != nil {
		return "", err
	}
	if !version.Newer(rel.TagName, version.Version) {
		return "", errors.New("обновлений нет")
	}
	asset, ok := rel.Asset(update.WindowsAsset)
	if !ok {
		return "", fmt.Errorf("в релизе %s нет Windows-архива", rel.TagName)
	}
	sums, ok := rel.Asset(func(n string) bool { return n == "SHA256SUMS.txt" })
	if !ok {
		return "", errors.New("в релизе нет SHA256SUMS.txt — скачивание отменено")
	}

	dir := filepath.Join(os.Getenv("LocalAppData"), "rupas", "updates", strings.TrimPrefix(rel.TagName, "v"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	zipPath := filepath.Join(dir, asset.Name)

	want, err := fetchSum(ctx, sums.URL, asset.Name)
	if err != nil {
		return "", err
	}
	if err := download(ctx, asset.URL, zipPath); err != nil {
		return "", err
	}
	got, err := fileSHA256(zipPath)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(got, want) {
		_ = os.Remove(zipPath)
		return "", fmt.Errorf("SHA256 не сошёлся для %s", asset.Name)
	}
	if err := unzip(zipPath, dir); err != nil {
		return "", err
	}
	return dir, nil
}

// OpenPath показывает папку или файл в проводнике.
func (c *Controller) OpenPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("пустой путь")
	}
	return exec.Command("explorer", path).Start()
}

// ApplyUpdate запускает подмену файлов и пер��запуск GUI.
//
// Сам swap делает отдельный cmd-скрипт: Windows не даёт перезаписать
// работающий .exe, а переименовать — даёт. Скрипт ждёт выхода rupas-gui,
// страхуется .old-копией и перезапускает приложение. Если скопировать не
// удалось (каталог под Program Files без прав), старый exe возвращается на
// место — установка остаётся рабочей.
func (c *Controller) ApplyUpdate(srcDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	appDir := filepath.Dir(exe)
	if _, err := os.Stat(filepath.Join(srcDir, "rupas-gui.exe")); err != nil {
		return fmt.Errorf("в %s нет rupas-gui.exe", srcDir)
	}

	script := filepath.Join(os.TempDir(), "rupas-update.cmd")
	body := fmt.Sprintf(`@echo off
set "APP=%s"
set "SRC=%s"
:wait
tasklist /fi "imagename eq rupas-gui.exe" 2>nul | find /i "rupas-gui.exe" >nul && (ping -n 2 127.0.0.1 >nul & goto wait)
taskkill /IM rupasd.exe /F >nul 2>&1
if exist "%%APP%%\rupas-gui.exe" ren "%%APP%%\rupas-gui.exe" "rupas-gui.old.exe"
xcopy /E /Y /I "%%SRC%%\*" "%%APP%%\" >nul
if not exist "%%APP%%\rupas-gui.exe" if exist "%%APP%%\rupas-gui.old.exe" ren "%%APP%%\rupas-gui.old.exe" "rupas-gui.exe"
start "" "%%APP%%\rupas-gui.exe"
del "%%~f0"
`, appDir, srcDir)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		return err
	}

	// Detached: the GUI has to die so the script can replace it.
	cmd := exec.Command("cmd", "/c", "start", "/min", "", script)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}()
	return nil
}

// OpenUpdatePage opens the release page in the default browser.
func (c *Controller) OpenUpdatePage() error {
	st := loadUpdateState()
	if st.URL == "" {
		return errors.New("ссылка на релиз неизвестна")
	}
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", st.URL).Start()
}

func fetchSum(ctx context.Context, url, assetName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("SHA256SUMS.txt: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		f := strings.Fields(strings.TrimPrefix(sc.Text(), "*"))
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == assetName {
			return string(f[0]), nil
		}
	}
	return "", fmt.Errorf("нет суммы для %s", assetName)
}

func download(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("скачивание: %s", resp.Status)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func unzip(path, dir string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		target := filepath.Join(dir, filepath.Clean("/"+f.Name)) // no path escape
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
