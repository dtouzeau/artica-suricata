package IPSets

import (
	"bufio"
	"fmt"
	"futils"
	"ipclass"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

const IprepDir = "/etc/suricata/iprep"

type IPBuild struct {
	SourcePath  string
	OutFileName string
	CategoryID  int
}

func Build(conf IPBuild) (error, int) {

	file, err := os.Open(conf.SourcePath)
	if err != nil {
		log.Error().Msgf("%v Unable to open reputation file: %v", futils.GetCalleRuntime(), err.Error())
		return err, 0
	}
	if conf.CategoryID == 0 {
		return fmt.Errorf("category id is mandatory ( current 0 )"), 0
	}

	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Create the directory if it doesn't exist

	futils.CreateDir(IprepDir)
	outputPath := filepath.Join(IprepDir, conf.OutFileName)
	outputFile, err := os.Create(outputPath)
	if err != nil {
		log.Error().Msgf("%v Unable to create output file: %v", futils.GetCalleRuntime(), err)
		return err, 0
	}
	defer func(outputFile *os.File) {
		_ = outputFile.Close()
	}(outputFile)

	scanner := bufio.NewScanner(file)
	d := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "/") {
			continue
		}

		line = strings.TrimPrefix(`0.0.0.0 `, line)
		line = strings.TrimPrefix(`127.0.0.1 `, line)
		line = strings.TrimSpace(line)
		if strings.Contains(line, "#") {
			tb := strings.Split(line, "#")
			line = tb[0]
		}

		if line == "0.0.0.0/8" || line == "127.0.0.0/8" || line == "192.168.0.0/16" || line == "10.0.0.0/8" || line == "172.16.0.0/12" {
			continue
		}
		IpStr := line

		if !ipclass.IsValidIPorCDIRorRange(IpStr) {
			continue
		}
		d++
		_, _ = outputFile.WriteString(fmt.Sprintf("%s,%d,127\n", IpStr, conf.CategoryID))
	}
	return nil, d
}
