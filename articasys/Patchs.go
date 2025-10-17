package articasys

import (
	"fmt"
	"github.com/leeqvip/gophp"
	"os"
	"path/filepath"
	"sockets"
	"strconv"
	"strings"
)

const ArticaRoot = "/usr/share/artica-postfix"

func ArticaMainVersion() string {
	base := ArticaRoot
	version, err := os.ReadFile(filepath.Join(base, "VERSION"))
	if err != nil {
		fmt.Printf("Error reading VERSION file: %v\n", err)
		return "0.0.0"
	}
	return strings.TrimSpace(string(version))
}

func PatchsBackup() bool {
	Realversion := ArticaMainVersion()
	baseWorkDir := filepath.Join("/home/artica/patchsBackup", Realversion)
	main := make(map[string]int64)

	if _, err := os.Stat(baseWorkDir); os.IsNotExist(err) {
		fmt.Printf("Directory does not exist: %s\n", baseWorkDir)
		mainSerialized, _ := gophp.Serialize(main)
		sockets.SET_INFO_STR("backuped_patchs", string(mainSerialized))
		return false
	}

	handle, err := os.Open(baseWorkDir)
	if err != nil {
		fmt.Printf("Error opening directory: %v\n", err)
		mainSerialized, _ := gophp.Serialize(main)
		sockets.SET_INFO_STR("backuped_patchs", string(mainSerialized))
		return false
	}
	defer handle.Close()

	files, err := handle.Readdirnames(-1)
	if err != nil {
		fmt.Printf("Error reading directory names: %v\n", err)
		mainSerialized, _ := gophp.Serialize(main)
		sockets.SET_INFO_STR("backuped_patchs", string(mainSerialized))
		return false
	}

	for _, filename := range files {
		if filename == "." || filename == ".." {
			continue
		}
		if _, err := strconv.Atoi(filename); err != nil {
			continue
		}
		backupDir := filepath.Join(baseWorkDir, filename)
		packageFile := filepath.Join(backupDir, "package.tgz")
		if fileInfo, err := os.Stat(packageFile); err == nil && !fileInfo.IsDir() {
			main[filename] = fileInfo.Size()
		}
	}
	mainSerialized, _ := gophp.Serialize(main)
	sockets.SET_INFO_STR("backuped_patchs", string(mainSerialized))
	return true
}
func DeleteAllServicePacks() bool {
	version := ArticaMainVersion()
	baseWorkDir := filepath.Join("/home/artica/patchsBackup", version)

	files, err := os.ReadDir(baseWorkDir)
	if err != nil {
		return false
	}

	for _, file := range files {
		if file.Name() == "." || file.Name() == ".." {
			continue
		}
		targetFile := filepath.Join(baseWorkDir, file.Name())
		if file.IsDir() {
			rmrf(targetFile)
		}
	}

	main := make(map[string]int64)
	mainSerialized, _ := gophp.Serialize(main)
	sockets.SET_INFO_STR("backuped_patchs", string(mainSerialized))
	return true
}
func rmrf(Directory string) error {

	if len(Directory) < 3 {
		return fmt.Errorf("Remove recusrively this base path %v is denied", Directory)
	}

	Denied := []string{"/root", "/home", "/var", "/lib", "/bin", "/usr", "/usr/lib", "/usr/share", "/etc",
		"/etc/init.d", "/opt", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin",
		"/usr/libexec", "/lib64", "/lib/x86_64-linux-gnu", "/proc", "/tmp", "/home/artica",
	}

	DeniedSuffix := []string{"/lib/x86_64-linux-gnu/", "/lib/", "/bin/", "/usr/sbin/", "/lib64/", "/usr/bin/"}

	for _, deniedP := range Denied {

		if Directory == deniedP {
			return fmt.Errorf("Remove recusrively this base path %v is denied", Directory)
		}
		Denied2 := fmt.Sprintf("%v/", deniedP)
		if Directory == Denied2 {
			return fmt.Errorf("Remove recusrively this base path %v/ is denied", Directory)
		}
	}

	for _, deniedP := range DeniedSuffix {

		if strings.HasPrefix(Directory, deniedP) {
			return fmt.Errorf("RmRF(): Remove recusrively this base path %v recusrsively is denied", Directory)
		}
	}

	if !isDirDirectory(Directory) {
		return nil
	}

	err := os.RemoveAll(Directory)
	if err != nil {
		return fmt.Errorf("RmRF(): Error while RemoveAll %v: %v", Directory, err)
	}
	return nil
}
func isDirDirectory(directoryPath string) bool {
	if isLink(directoryPath) {
		link, err := os.Readlink(directoryPath)
		if err != nil {
			return false
		}
		directoryPath = link
	}

	fileinfo, err := os.Stat(directoryPath)
	if err != nil {
		return false
	}

	if os.IsNotExist(err) {
		return false
	}
	return fileinfo.IsDir()
}
func isLink(path string) bool {

	info, err := os.Lstat(path)
	if err != nil {
		return false
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return false
}
