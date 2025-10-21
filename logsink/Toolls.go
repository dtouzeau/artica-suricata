package logsink

import (
	"encoding/json"
	"fmt"
	"futils"
	"github.com/leeqvip/gophp"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"notifs"
	"os"
	"path/filepath"
	"regexp"
	"sockets"
	"sort"
	"strconv"
	"strings"
)

type SysHost struct {
	Logs map[string]SysHost
	Size int64  `json:"Size"`
	Path string `json:"Path,omitempty"`
}

type RsyslogDiscover struct {
	AllDates  map[string]bool    `json:"AllDates"`
	FileNames map[string]SysHost `json:"FileNames"`
}

func DiscoverDirectories() RsyslogDiscover {
	ProgressF := "logs-sink-refresh.progress"
	var r RsyslogDiscover
	enableSyslogLogSink := sockets.GET_INFO_INT("EnableSyslogLogSink")
	if enableSyslogLogSink == 0 {
		notifs.BuildProgress(110, "{failed}", ProgressF)
		return r
	}

	logSinkWorkDir := sockets.GET_INFO_STR("LogSinkWorkDir")
	if logSinkWorkDir == "" {
		logSinkWorkDir = "/home/syslog/logs_sink"
	}
	destinationDir := logSinkWorkDir

	files, err := ioutil.ReadDir(destinationDir)
	if err != nil {
		notifs.BuildProgress(110, "{failed}", ProgressF)
		return r
	}

	maxFiles := len(files)
	c := 0

	r.FileNames = make(map[string]SysHost)
	r.AllDates = make(map[string]bool)
	for _, file := range files {
		if !file.IsDir() {
			continue
		}
		c++
		notifs.BuildProgress(110, "{failed}", ProgressF)
		pr1 := (c * 100) / maxFiles
		if pr1 > 98 {
			pr1 = 98
		}
		notifs.BuildProgress(pr1, fmt.Sprintf("{analyze} %s", filepath.Join(destinationDir, file.Name())), ProgressF)

		dirSize := DirsizeBytes(filepath.Join(destinationDir, file.Name()))
		fname := file.Name()
		var s SysHost
		s.Logs = make(map[string]SysHost)
		s.Size = dirSize
		r.FileNames[fname] = s

		subFiles, err := ioutil.ReadDir(filepath.Join(destinationDir, file.Name()))
		if err != nil {
			continue
		}
		var sz SysHost
		sz.Logs = make(map[string]SysHost)

		for _, subFile := range subFiles {
			if !subFile.Mode().IsRegular() || !regexp.MustCompile(`\.gz$`).MatchString(subFile.Name()) {
				continue
			}
			notifs.BuildProgress(pr1, fmt.Sprintf("{analyze} %s", subFile.Name()), ProgressF)
			if match := regexp.MustCompile(`^(.+?)_`).FindStringSubmatch(subFile.Name()); match != nil {
				r.AllDates[match[1]] = true

			}
			var st SysHost
			st.Size = subFile.Size()
			st.Path = filepath.Join(destinationDir, file.Name(), subFile.Name())
			r.FileNames[fname].Logs[subFile.Name()] = st
		}

	}
	notifs.BuildProgress(100, "{success}", ProgressF)
	jsonBytes, _ := json.MarshalIndent(r, "", "  ")
	sockets.SET_INFO_STR("SyslogSinkStatus", string(jsonBytes))
	return r
}
func DirsizeBytes(dir string) int64 {
	var size int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		size += info.Size()
		return nil
	})
	if err != nil {
		return 0
	}
	return size
}
func rsyslogQueueSize() bool {
	// Calculate the size of the rsyslog queue directory
	rsyslogQueueDir := "/var/spool/rsyslog"
	queueSize := DirsizeBytes(rsyslogQueueDir)
	log.Debug().Msgf("%v Syslog Queue Size: %d bytes", futils.GetCalleRuntime(), queueSize)
	sockets.SET_INFO_INT("rsyslog_queue_size", queueSize)

	syslogSpoolDir := "/home/artica/syslog/spool"
	futils.CreateDir(syslogSpoolDir)

	rsyslogQueuesSize := make(map[string]int64)
	dirs, err := os.ReadDir(syslogSpoolDir)
	if err != nil {
		log.Error().Msgf("%v Error reading directory %s: %v", futils.GetCalleRuntime(), syslogSpoolDir, err)
		return true
	}

	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		dirName := dir.Name()
		if dirName == "." || dirName == ".." {
			continue
		}
		if _, err := strconv.Atoi(dirName); err != nil {
			continue
		}
		fullPath := filepath.Join(syslogSpoolDir, dirName)
		rsyslogQueuesSize[dirName] = DirsizeBytes(fullPath)
	}
	return true
}
func CleanQueues() {
	FProgress := "rsyslog.clean.progress"
	rm := futils.FindProgram("rm")

	files, err := os.ReadDir("/var/spool/rsyslog")
	if err != nil {
		log.Error().Msgf("%v Error reading directory: %v", futils.GetCalleRuntime(), err)
		notifs.BuildProgress(110, "Error reading directory", FProgress)
	}

	count := len(files)
	for c, file := range files {
		filename := file.Name()
		if filename == "." || filename == ".." {
			continue
		}

		prc := int(float64(c+1) / float64(count) * 100)
		if prc > 85 {
			prc = 85
		}
		notifs.BuildProgress(prc, fmt.Sprintf("{cleaning2} %s", filename), FProgress)

		path := filepath.Join("/var/spool/rsyslog", filename)
		if file.IsDir() {
			_, _ = futils.ExecuteShell(fmt.Sprintf("%v -rf %v", rm, path))
			continue
		}
		_ = os.Remove(path)

	}

	rsyslogQueueSize()
	notifs.BuildProgress(100, "{done}", FProgress)

}

func RemoveHost(hostname string) {
	hostname = strings.TrimSpace(hostname)
	if len(hostname) < 2 {
		return
	}
	LogSinkWorkDir := sockets.GET_INFO_STR("LogSinkWorkDir")
	if len(LogSinkWorkDir) < 3 {
		LogSinkWorkDir = "/home/syslog/logs_sink"
	}

	DestinationDir := fmt.Sprintf("%v/%v", LogSinkWorkDir, hostname)
	if !futils.IsDirDirectory(DestinationDir) {
		return
	}
	futils.RmRF(DestinationDir)
	BuildLogsSink()
}

func BuildLogsSink() bool {
	ProgressF := "logs-sink-refresh.progress"
	enableSyslogLogSink := sockets.GET_INFO_INT("EnableSyslogLogSink")
	if enableSyslogLogSink == 0 {
		notifs.BuildProgress(110, "{failed}", ProgressF)
		return false
	}

	logSinkWorkDir := sockets.GET_INFO_STR("LogSinkWorkDir")
	if logSinkWorkDir == "" {
		logSinkWorkDir = "/home/syslog/logs_sink"
	}

	files, err := os.ReadDir(logSinkWorkDir)
	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
		return false
	}

	maxFiles := len(files)
	syslogSinkStatus := make(map[string]map[string]string)
	c := 0

	for _, file := range files {
		if !file.IsDir() || file.Name() == "." || file.Name() == ".." {
			continue
		}

		c++
		notifs.BuildProgress(110, "{failed}", ProgressF)
		pr1 := int(float64(c) / float64(maxFiles) * 100)
		if pr1 > 98 {
			pr1 = 98
		}
		notifs.BuildProgress(pr1, fmt.Sprintf("{analyze} %s", file.Name()), ProgressF)

		dirPath := filepath.Join(logSinkWorkDir, file.Name())
		syslogSinkStatus[file.Name()] = map[string]string{
			"SIZE": futils.Int64ToString(DirsizeBytes(dirPath)),
		}

		var subfiles []string
		subFiles, err := os.ReadDir(dirPath)
		if err != nil {
			fmt.Printf("Error reading subdirectory: %v\n", err)
			continue
		}

		sort.Slice(subFiles, func(i, j int) bool {
			return subFiles[i].Name() > subFiles[j].Name()
		})

		for _, subFile := range subFiles {
			if subFile.Name() == "." || subFile.Name() == ".." || !strings.HasSuffix(subFile.Name(), ".gz") {
				continue
			}

			notifs.BuildProgress(pr1, fmt.Sprintf("{analyze} %s", subFile.Name()), ProgressF)

			if matches := regexp.MustCompile(`^(.+?)_`).FindStringSubmatch(subFile.Name()); len(matches) > 1 {
				if _, exists := syslogSinkStatus["ALL_DATES"]; !exists {
					syslogSinkStatus["ALL_DATES"] = make(map[string]string)
				}
				syslogSinkStatus["ALL_DATES"][matches[1]] = "true"
				SubPath := filepath.Join(dirPath, subFile.Name())
				Fsize := futils.FileSize(SubPath)
				subfiles = append(subfiles, fmt.Sprintf("%v|%d|%v", subFile.Name(), Fsize, SubPath))
				syslogSinkStatus[file.Name()]["LOGS"] = fmt.Sprintf("%v|%d|%v", subFile.Name(), Fsize, SubPath)
			}
		}
		serialized, _ := gophp.Serialize(subfiles)
		serialized_text := fmt.Sprintf("%s", serialized)
		syslogSinkStatus[file.Name()]["LOGS"] = serialized_text
	}

	notifs.BuildProgress(100, "{success}", ProgressF)
	serialized, _ := gophp.Serialize(syslogSinkStatus)
	serialized_text := fmt.Sprintf("%s", serialized)
	sockets.SET_INFO_STR("SyslogSinkStatus", serialized_text)

	return true
}
