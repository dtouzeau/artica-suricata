package SuricataTools

import (
	"SuricataService"
	"apostgres"
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"futils"
	"net"
	"notifs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"surisock"
	"time"

	"github.com/rs/zerolog/log"
)

const ProgressF = "suricata.progress"
const PidPath = SuricataService.PidPath

var RegexLocation = regexp.MustCompile(`^(.+?)\s+\(Line:\s+([0-9]+)\)`)

func FixDuplicateRules() {

	_, duplicateMap := findDuplicateSignatures()

	log.Warn().Msgf("%v found %d duplicate signatures", futils.GetCalleRuntime(), len(duplicateMap))
	if len(duplicateMap) > 0 {
		commentOutDuplicates(duplicateMap)
	}
}
func commentOutDuplicates(duplicateMap map[string][]string) {
	for sid, locations := range duplicateMap {

		for _, loc := range locations {
			log.Debug().Msgf("%v Duplicate sid:%s found at location:%v", futils.GetCalleRuntime(), sid, loc)
			filePath, lineNumber := parseLocation(loc)
			log.Warn().Msgf("%v Commenting out sid:%s in file: %s at line: %d", futils.GetCalleRuntime(), sid, filePath, lineNumber)
			err := modifyRuleFile(filePath, lineNumber)
			if err != nil {
				log.Error().Msgf("%v Unable to modify rule file [%v] Line:%d", futils.GetCalleRuntime(), filePath, lineNumber)
			}
		}
	}
}
func modifyRuleFile(filePath string, lineNumber int) error {
	inputFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("Error opening file: %s", err)
	}
	defer inputFile.Close()

	// Create a temporary output file to write the modified content
	tempFilePath := filePath + ".tmp"
	outputFile, err := os.Create(tempFilePath)
	if err != nil {
		return fmt.Errorf("Error creating temporary file: %s", err)
	}
	defer outputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	writer := bufio.NewWriter(outputFile)

	currentLine := 0
	for scanner.Scan() {
		currentLine++
		line := scanner.Text()
		if currentLine == lineNumber {
			if !strings.HasPrefix(line, "#") {
				line = "# " + line
			}
		}
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("Error writing to temporary file: %s", err)
		}
	}
	writer.Flush()
	err = os.Rename(tempFilePath, filePath)
	if err != nil {
		return fmt.Errorf("Error replacing original file: %s", err)
	}

	return nil
}
func parseLocation(location string) (string, int) {

	log.Debug().Msgf("%v Location [%v]", futils.GetCalleRuntime(), location)
	filePath, line := futils.RegexGroup2(RegexLocation, location)
	if len(filePath) == 0 {
		log.Debug().Msgf("%v Location [%v] is not understrood", futils.GetCalleRuntime(), location)
		return "", -1

	}
	lineNumber := futils.StrToInt(line)
	fmt.Sscanf(filePath, "%d", &lineNumber)
	return filePath, lineNumber
}
func findDuplicateSignatures() (map[string]string, map[string][]string) {
	// Regex to match sid (Signature ID) in Suricata rule format: sid:<id>;
	ruleDir := "/etc/suricata/rules"
	ruleSidPattern := regexp.MustCompile(`sid:(\d+);`)
	// Map to track sids and their corresponding file
	sidMap := make(map[string]string)
	// Map to track duplicate sids
	duplicateMap := make(map[string][]string)

	// Walk through all files in the rule directory
	filepath.Walk(ruleDir, func(path string, info os.FileInfo, err error) error {
		// Only process files with .rules extension
		if filepath.Ext(path) == ".rules" {
			file, err := os.Open(path)
			if err != nil {
				fmt.Printf("Error opening file: %s\n", path)
				return nil
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			lineNumber := 0
			for scanner.Scan() {
				lineNumber++
				line := scanner.Text()

				// Skip commented lines
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}

				// Check if line contains an `sid`
				match := ruleSidPattern.FindStringSubmatch(line)
				if len(match) > 1 {
					sid := match[1]
					// Check if sid already exists in sidMap
					if existingFile, found := sidMap[sid]; found {
						// Duplicate found
						duplicateMap[sid] = append(duplicateMap[sid], fmt.Sprintf("%s (Line: %d)", existingFile, lineNumber))
						duplicateMap[sid] = append(duplicateMap[sid], fmt.Sprintf("%s (Line: %d)", path, lineNumber))
					} else {
						sidMap[sid] = fmt.Sprintf("%s (Line: %d)", path, lineNumber)
					}
				}
			}
		}
		return nil
	})

	return sidMap, duplicateMap
}
func Reload() {
	pid := GetPID()
	if !futils.ProcessExists(pid) {
		notifs.BuildProgress(110, "{reloading} {failed} {stopped}", ProgressF)
		return
	}

	notifs.BuildProgress(30, "{reloading}", ProgressF)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Reload full YAML + rules:
	if Reply, err := surisock.RulesetReloadNonBlocking(ctx); err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		notifs.BuildProgress(110, "{reloading} {failed} "+err.Error(), ProgressF)
		if Reply != nil {
			if Reply.Return != "OK" {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), Reply.Message)
			}
		}
		return
	}

	notifs.BuildProgress(100, "{reloading} {success}", ProgressF)
}
func GetPID() int {

	pid := futils.GetPIDFromFile(PidPath)
	if futils.ProcessExists(pid) {
		return pid
	}
	Binary := futils.FindProgram("suricata")

	if len(Binary) < 3 {
		return 0
	}
	return futils.PIDOFPattern("suricata --pidfile")
}
func GetDisabledSignatures() (error, []string) {
	conn, err := apostgres.SQLConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return fmt.Errorf("failed to connect to database: %v", err), []string{}
	}
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)

	query := "SELECT signature FROM suricata_sig WHERE enabled=0"
	rows, err := conn.Query(query)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return fmt.Errorf("failed to execute query: %v", err), []string{}
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	var suppressRules []string
	for rows.Next() {
		var signature string
		err := rows.Scan(&signature)
		if err != nil {
			return fmt.Errorf("failed to scan row: %v", err), []string{}
		}
		suppressRules = append(suppressRules, signature)
	}

	return nil, suppressRules
}
func dumpCounters() (string, string, error) {
	const bin = "/usr/bin/suricatasc"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-c", "dump-counters", "/run/suricata/suricata.sock")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = futils.ExecEnv()
	err := cmd.Run()

	// Distinguish timeout explicitly
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stdout.String(), stderr.String(),
			fmt.Errorf("suricatasc timed out after 20s: %w", context.DeadlineExceeded)
	}

	// Non-zero exit or other exec errors
	if err != nil {
		return stdout.String(), stderr.String(),
			fmt.Errorf("suricatasc failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), stderr.String(), nil
}
func DumpStats() (SuricataStats, string) {
	var Res SuricataStats
	out, serr, err := dumpCounters()
	if err != nil {
		log.Error().Msgf("%v %v [%v]/[%v]", futils.GetCalleRuntime(), err.Error(), out, serr)
		if strings.Contains(serr, "Connection refused") {
			go func() {
				err := SuricataService.Start()
				if err != nil {
					log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
				}
			}()
			return Res, ""
		}

		return Res, ""
	}
	err = json.Unmarshal([]byte(out), &Res)
	if err != nil {
		log.Error().Msgf("%v Error unmarshaling JSON: %v", futils.GetCalleRuntime(), err.Error())
		return Res, ""
	}
	return Res, out
}
func UnixCommand(order string) (error, string) {
	socketPath := "/var/run/suricata/suricata.sock"
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Printf("Failed to connect to Suricata socket: %v\n", err)
		os.Exit(1)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)
	command := fmt.Sprintf(`{"command": "%v"}`, order)
	log.Debug().Msgf("%v Command: %v", futils.GetCalleRuntime(), command)

	_, err = conn.Write([]byte(command + "\n"))
	if err != nil {
		return fmt.Errorf("%v failed to send command: %v", futils.GetCalleRuntime(), err), ""

	}
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("%v failed to read response: %v", futils.GetCalleRuntime(), err), ""

	}
	response := string(buffer[:n])
	return nil, response

}
