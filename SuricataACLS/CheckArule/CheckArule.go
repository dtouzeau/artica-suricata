package CheckArule

import (
	"context"
	"fmt"
	"futils"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

func CheckSuricataRule(rule, suricata, yaml string) (string, error) {
	dir, err := os.MkdirTemp("", "suri-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	ruleFile := filepath.Join(dir, "test.rules")
	if err := os.WriteFile(ruleFile, []byte(rule+"\n"), 0644); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, suricata,
		"-T", "-c", yaml,
		"-S", ruleFile, // exclusive load: only this file
		"-vv", "--init-errors-fatal",
	)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("timeout")
	}
	return string(out), err
}

func CheckRule(rule string) error {
	suricata := futils.FindProgram("suricata")
	log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), rule)
	out, err := CheckSuricataRule(rule, suricata, "/etc/suricata/suricata.yaml")
	fmt.Println(out)
	if err != nil {
		return fmt.Errorf("ERROR: %v (%v)", err, out)
	}
	return nil
}
