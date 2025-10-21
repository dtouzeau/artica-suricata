package logrotate

import (
	"amount"
	"bufio"
	"compressor"
	"encoding/json"
	"fmt"
	"futils"
	"notifs"
	"os"
	"sockets"
	"strings"
	"suricata"
	"time"

	"github.com/rs/zerolog/log"
)

func RotateEveJsonByPeriod() {
	logFile := "/var/log/suricata/eve.json"
	if !futils.FileExists(logFile) {
		return
	}

	SquidRotateOnlySchedule := sockets.GET_INFO_INT("SquidRotateOnlySchedule")
	if SquidRotateOnlySchedule == 1 {
		log.Debug().Msgf("%v Rotation only by schedule, aborting", futils.GetCalleRuntime())
		return
	}

	LogsRotateDefaultSizeRotation := sockets.GET_INFO_INT("LogsRotateDefaultSizeRotation")
	if LogsRotateDefaultSizeRotation < 5 {
		LogsRotateDefaultSizeRotation = 100
	}

	CurrentSize := futils.FileSizeMB(logFile)
	log.Debug().Msgf("%v %dMB <> %dMB", futils.GetCalleRuntime(), CurrentSize, LogsRotateDefaultSizeRotation)
	if CurrentSize < LogsRotateDefaultSizeRotation {
		return
	}

}
func getAutomountPath() (error, string) {

	SquidRotateAutomountRes := sockets.GET_INFO_STR("SquidRotateAutomountRes")
	SquidRotateAutomountFolder := sockets.GET_INFO_STR("SquidRotateAutomountFolder")
	AutomountPath := fmt.Sprintf("/automounts/%v", SquidRotateAutomountRes)

	_ = futils.DirectoryScan(AutomountPath)
	if !ifDirMounted(AutomountPath) {
		return fmt.Errorf("%v AutomountPath %v not mounted", futils.GetCalleRuntime(), AutomountPath), ""
	}

	Target := fmt.Sprintf("%v/%v", AutomountPath, SquidRotateAutomountFolder)
	if !futils.IsDirDirectory(Target) {
		err := os.MkdirAll(Target, 0755)
		if err != nil {
			return fmt.Errorf("%v AutomountPath %v Permission denied", futils.GetCalleRuntime(), AutomountPath), ""
		}
	}

	TempF := futils.TimeStampToString()
	err := futils.FilePutContents(fmt.Sprintf("%v/%v", Target, TempF), TempF)
	if err != nil {
		return fmt.Errorf("%v AutomountPath %v Permission denied", futils.GetCalleRuntime(), AutomountPath), ""
	}

	return nil, Target
}

func GetBackupMaxDaysDir() (error, string) {

	SquidRotateAutomount := sockets.GET_INFO_INT("SquidRotateAutomount")
	BackupSquidLogsUseNas := sockets.GET_INFO_INT("BackupSquidLogsUseNas")
	if SquidRotateAutomount == 1 {
		return getAutomountPath()
	}
	BackupMaxDaysDir := sockets.GET_INFO_STR("BackupMaxDaysDir")

	if len(BackupMaxDaysDir) < 3 {
		BackupMaxDaysDir = "/home/logrotate_backup"
	}

	if BackupSquidLogsUseNas == 0 {
		return nil, BackupMaxDaysDir
	}
	MountPoint := "/mnt/BackupSquidLogsUseNas"
	BackupSquidLogsNASFolder2 := sockets.GET_INFO_STR("BackupSquidLogsNASFolder2")
	if len(BackupSquidLogsNASFolder2) < 3 {
		BackupSquidLogsNASFolder2 = "artica-backup-syslog"
	}

	futils.CreateDir(MountPoint)
	err := MountTONas()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return err, ""
	}
	return nil, fmt.Sprintf("%v/%v", MountPoint, BackupSquidLogsNASFolder2)

}

func RotateEveJson() {
	logFile := "/var/log/suricata/eve.json"
	if !futils.FileExists(logFile) {
		return
	}
	LogRotatePath := sockets.GET_INFO_STR("LogRotatePath")
	if len(LogRotatePath) == 0 {
		LogRotatePath = "/home/logrotate"
	}

	Fsize := futils.FileSizeMB(logFile)
	notifs.TosyslogGen(fmt.Sprintf("%v Perform log rotation rotation of IDS events (%vMB)", futils.GetCalleRuntime(), Fsize), "logrotate")

	timestamp := futils.TimeStampToString()
	futils.CreateDir(LogRotatePath)
	Logtemp := fmt.Sprintf("%v/%v.suricata.json", LogRotatePath, timestamp)
	log.Debug().Msgf("%v Move %v -> %v", futils.GetCalleRuntime(), logFile, Logtemp)
	err := futils.MoveFile(logFile, Logtemp)
	if err != nil {
		notifs.TosyslogGen(fmt.Sprintf("%v ERROR Unable to move %v to %v", futils.GetCalleRuntime(), logFile, Logtemp), "logrotate")
		notifs.SquidAdminMysql(1, fmt.Sprintf("Unable to move %v to %v", logFile, Logtemp), err.Error(), futils.GetCalleRuntime(), 39)
		return
	}
	log.Warn().Msgf("%v Reloading Suricata", futils.GetCalleRuntime())
	Pid := suricata.GetPID()
	if futils.ProcessExists(Pid) {
		futils.KillReloadProcess(Pid)
	}

	TimeStart, TimeEnd := EveJsonDates(Logtemp)
	Start := futils.TimeStampDecompose(TimeStart)
	End := futils.TimeStampDecompose(TimeEnd)

	err, BackupMaxDaysDir := GetBackupMaxDaysDir()

	if err != nil {
		log.Error().Msgf("%v Error getting backup max days dir: %v", futils.GetCalleRuntime(), err)
		return
	}

	FinalDirectory := fmt.Sprintf("%v/proxy/%d/%d/%d", BackupMaxDaysDir, End.Year, End.Month, End.Day)
	futils.CreateDir(FinalDirectory)
	fname := fmt.Sprintf("ids-%v-%v-%v-%v_%v-%v-%v-%v.gz", Start.Year, Start.Month, Start.Day, Start.Hour, End.Year, End.Month, End.Day, End.Hour)
	FinalName := fmt.Sprintf("%v/%v", FinalDirectory, fname)
	log.Debug().Msgf("%v Compressing %v -> %v", futils.GetCalleRuntime(), Logtemp, FinalName)
	err = compressor.CompressGZ(Logtemp, FinalName)
	if err != nil {
		notifs.TosyslogGen(fmt.Sprintf("%v ERROR Compression failed to %v %v", futils.GetCalleRuntime(), FinalName, err.Error()), "logrotate")
		notifs.SquidAdminMysql(1, fmt.Sprintf("Unable to Compress %v to %v", fname, FinalDirectory), err.Error(), futils.GetCalleRuntime(), 68)
		return
	}
	futils.DeleteFile(Logtemp)
	notifs.TosyslogGen(fmt.Sprintf("%v Success rotate IDS legal log %v to long-term storage dir", futils.GetCalleRuntime(), FinalName), "logrotate")

}
func EveJsonDates(TmpFile string) (string, string) {
	Lines := futils.FileHead10(TmpFile)
	location, _ := time.LoadLocation("Local")

	TimeStampStart := ""
	TimeStampStop := ""
	for _, line := range Lines {

		var mainEvent suricata.SuricataEvent

		err := json.Unmarshal([]byte(line), &mainEvent)
		if err != nil {
			log.Error().Msgf("%v Error unmarshalling JSON:%v [%v]", futils.GetCalleRuntime(), err, line)
			continue
		}
		mainEvent.Timestamp = suricata.FixTimeFormat(mainEvent.Timestamp)
		parsedTime, err := time.ParseInLocation("2006-01-02T15:04:05.999999999-07:00", mainEvent.Timestamp, location)
		if err != nil {
			log.Error().Msgf("%v Error parsing timestamp: %v", futils.GetCalleRuntime(), err)
			continue

		}
		unixTimestamp := parsedTime.Unix()
		TimeStampStart = fmt.Sprintf("%d", unixTimestamp)
	}

	Lines = futils.FileTail10(TmpFile)
	for _, line := range Lines {
		var mainEvent suricata.SuricataEvent

		err := json.Unmarshal([]byte(line), &mainEvent)
		if err != nil {
			log.Error().Msgf("%v Error unmarshalling JSON:%v [%v]", futils.GetCalleRuntime(), err, line)
			continue
		}
		mainEvent.Timestamp = suricata.FixTimeFormat(mainEvent.Timestamp)
		parsedTime, err := time.ParseInLocation("2006-01-02T15:04:05.999999999-07:00", mainEvent.Timestamp, location)
		if err != nil {
			log.Error().Msgf("%v Error parsing timestamp: %v", futils.GetCalleRuntime(), err)
			continue

		}
		unixTimestamp := parsedTime.Unix()
		TimeStampStop = fmt.Sprintf("%d", unixTimestamp)
	}

	return TimeStampStart, TimeStampStop
}
func ifDirMounted(directory string) bool {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		log.Error().Msgf("%v Error opening /proc/mounts:", futils.GetCalleRuntime(), err)
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, directory) {
			return true
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading /proc/mounts:", err)
		return false
	}

	return false
}
func MountTONas() error {
	var Opts amount.ShareSettings
	Opts.MountPoint = "/mnt/BackupArticaBackNAS"
	Opts.Hostname = sockets.GET_INFO_STR("BackupArticaBackNASIpaddr")
	Opts.ShareFolder = sockets.GET_INFO_STR("BackupArticaBackNASFolder")
	Opts.UserName = sockets.GET_INFO_STR("BackupArticaBackNASUser")
	Opts.Password = sockets.GET_INFO_STR("BackupArticaBackNASPassword")

	futils.CreateDir(Opts.MountPoint)

	err := amount.SmbShare(Opts)
	if err != nil {
		_ = amount.Unmount("/mnt/BackupArticaBackNAS")
		notifs.SquidAdminMysql(0, "Mounting NAS filesystem return error", err.Error(), "SnapShotToNas", 117)
		return fmt.Errorf(fmt.Sprintf("%v Mounting NAS filesystem return error %v", futils.GetCalleRuntime(), err.Error()))

	}

	SharedWorkdir := sharedStorageDir()
	log.Info().Msg(fmt.Sprintf("%v Storage directory [%v]", futils.GetCalleRuntime(), SharedWorkdir))
	futils.CreateDir(SharedWorkdir)
	if !futils.IsDirDirectory(SharedWorkdir) {
		_ = amount.Unmount("/mnt/BackupArticaBackNAS")
		log.Error().Msg(fmt.Sprintf("%v %v Permissions denied", futils.GetCalleRuntime(), SharedWorkdir))
		return fmt.Errorf(fmt.Sprintf("%v %v Permission denied on this directory", futils.GetCalleRuntime(), SharedWorkdir))
	}
	TmpFile := futils.TimeStampToString()
	TmpPath := fmt.Sprintf("%v/%v", SharedWorkdir, TmpFile)
	err = futils.FilePutContents(TmpPath, "\n")
	if err != nil {
		_ = amount.Unmount("/mnt/BackupArticaBackNAS")
		return fmt.Errorf(fmt.Sprintf("%v %v %v Permission denied", futils.GetCalleRuntime(), TmpPath, err.Error()))
	}
	futils.DeleteFile(TmpPath)
	return nil
}
func sharedStorageDir() string {
	hostname, _ := futils.GetHostnameFqdn()
	BackupArticaBackNASFolder2 := sockets.GET_INFO_STR("BackupArticaBackNASFolder2")
	if len(BackupArticaBackNASFolder2) > 2 {
		BackupArticaBackNASFolder2 = futils.StripLeadingSlash(BackupArticaBackNASFolder2)
		SharedWorkdir := fmt.Sprintf("%v/%v/%v/snapshots", "/mnt/BackupArticaBackNAS", BackupArticaBackNASFolder2, hostname)
		return SharedWorkdir
	}
	SharedWorkdir := fmt.Sprintf("%v/%v/snapshots", "/mnt/BackupArticaBackNAS", hostname)
	return SharedWorkdir
}
