package LogSinkSearcher

import (
	"bufio"
	"errors"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sockets"
	"strings"
	"time"
)

const ProgressDir = "/usr/share/artica-postfix/ressources/logs/web"

type ringTail struct {
	max   int
	buf   []string
	start int
	size  int
}

func workDir() string {
	LogSinkWorkDir := sockets.GET_INFO_STR("LogSinkWorkDir")
	if len(LogSinkWorkDir) < 2 {
		LogSinkWorkDir = "/home/syslog/logs_sink"
	}
	return LogSinkWorkDir
}
func LogsSinkSearcher(date int64, host string, search string, fname string, rows int) error {

	if host == "" || host == "all" {
		host = "*" // wildcard like PHP
	}

	if fname == "" {
		return fmt.Errorf("fname is empty")
	}

	if rows < 200 {
		rows = 200
	}
	progressFile := filepath.Join(ProgressDir, fname+".sh")
	tmpfile := filepath.Join(ProgressDir, fname+".log")

	// Start background job (like nohup &)
	go func() {
		if err := runSearch(date, host, search, rows, tmpfile, progressFile); err != nil {
			_ = os.WriteFile(tmpfile, []byte("ERROR: "+err.Error()+"\n"), 0644)
			_ = futils.FilePutContents(progressFile, "110")
			return
		}
		_ = futils.FilePutContents(progressFile, "100")
	}()
	return nil
}
func runSearch(date int64, hostPattern, search string, rows int, outPath string, progressFile string) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("ensure progress dir: %w", err)
	}
	// Build optional prefix YYYY-MM-DD_
	prefix := ""
	if date > 5 {
		prefix = time.Unix(date, 0).UTC().Format("2006-01-02") + "_"
	}

	hostGlob := filepath.Join(workDir(), hostPattern)
	hostDirs, err := filepath.Glob(hostGlob)
	if err != nil {
		return fmt.Errorf("host glob: %w", err)
	}
	if len(hostDirs) == 0 {
		return fmt.Errorf("no hosts matched %q", hostGlob)
	}

	// Tail buffer (like `| tail -n rows`)
	tail := newTail(rows)

	// Locate zgrep
	zgrepPath := futils.FindProgram("zgrep")
	Max := len(hostDirs)
	c := 30
	_ = futils.FilePutContents(progressFile, fmt.Sprintf("%v", "30"))
	futils.ChownFile(progressFile, "www-data", "www-data")
	// Walk each host directory recursively, process files that match prefix + *.gz
	for _, dir := range hostDirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
			prc := float64(c) / float64(Max)
			prc = math.Round(prc * 100)
			if prc > 30 {
				if prc > 98 {
					prc = 98
				}
			}
			_ = futils.FilePutContents(progressFile, fmt.Sprintf("%v", futils.Float64ToInt(prc)))
			futils.ChownFile(progressFile, "www-data", "www-data")
			if walkErr != nil {
				return nil // skip errors but continue
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".gz") {
				return nil
			}
			if prefix != "" && !strings.HasPrefix(name, prefix) {
				return nil
			}
			// zgrep -E -i -e <search> <file>
			cmd := exec.Command(zgrepPath, "-E", "-i", "-e", search, path)
			out, err := cmd.CombinedOutput() // includes stderr (like 2>&1)
			// zgrep exit code 1 means "no matches" — not an error for us
			if err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) && ee.ExitCode() == 1 {
					// no matches; ignore
				} else if len(out) == 0 {
					// real error
					log.Error().Msgf("%v zgrep error on %s: %v", err.Error(), path, err)
				}
			}
			if len(out) > 0 {
				sc := bufio.NewScanner(strings.NewReader(string(out)))
				// avoid Scan() token size limits if lines can be huge
				buf := make([]byte, 0, 1024*1024)
				sc.Buffer(buf, 10*1024*1024)
				for sc.Scan() {
					tail.Add(sc.Text())
				}
			}
			return nil
		})
	}

	// Write result atomically
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(tail.Lines(), "\n")+"\n"), 0644); err != nil {
		_ = futils.FilePutContents(progressFile, fmt.Sprintf("%v", "110"))
		futils.ChownFile(progressFile, "www-data", "www-data")
		return fmt.Errorf("write tmp: %w", err)
	}
	_ = futils.FilePutContents(progressFile, fmt.Sprintf("%v", "95"))
	futils.ChownFile(progressFile, "www-data", "www-data")
	return os.Rename(tmp, outPath)
}
func newTail(n int) *ringTail { return &ringTail{max: n, buf: make([]string, n)} }
func (t *ringTail) Add(s string) {
	if t.max == 0 {
		return
	}
	if t.size < t.max {
		t.buf[t.size] = s
		t.size++
		return
	}
	t.buf[t.start] = s
	t.start = (t.start + 1) % t.max
}
func (t *ringTail) Lines() []string {
	if t.size == 0 {
		return nil
	}
	if t.size < t.max {
		return append([]string(nil), t.buf[:t.size]...)
	}
	out := make([]string, t.max)
	copy(out, t.buf[t.start:])
	copy(out[t.max-t.start:], t.buf[:t.start])
	return out
}
