package compressor

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sockets"
	"strings"
	"time"
	"unicode"
)

type TarFormat string

const (
	TarFormatGzip    TarFormat = "gzip"
	TarFormatBzip2   TarFormat = "bzip2"
	TarFormatXz      TarFormat = "xz"
	TarFormatTar     TarFormat = "tar"
	TarFormatUnknown TarFormat = "unknown"
)

func DetectFormat(filePath string) (TarFormat, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return TarFormatUnknown, fmt.Errorf("failed to open file: %w", err)
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	magic := make([]byte, 6)
	_, err = f.Read(magic)
	if err != nil {
		return TarFormatUnknown, fmt.Errorf("failed to read header: %w", err)
	}

	switch {
	case bytes.HasPrefix(magic, []byte{0x1F, 0x8B}):
		return TarFormatGzip, nil
	case bytes.HasPrefix(magic, []byte{0x42, 0x5A}): // "BZ"
		return TarFormatBzip2, nil
	case bytes.HasPrefix(magic, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}):
		return TarFormatXz, nil
	default:
		return TarFormatTar, nil // assume uncompressed TAR (no magic)
	}
}
func extractTarGz(gzipStream io.Reader, targetDir string) error {
	unzippedStream, err := gzip.NewReader(gzipStream)

	if err != nil {
		return fmt.Errorf("gzip.NewReader() Error %v", err.Error())

	}
	defer func(unzippedStream *gzip.Reader) {
		err := unzippedStream.Close()
		if err != nil {

		}
	}(unzippedStream)
	tarReader := tar.NewReader(unzippedStream)
	for {
		header, err := tarReader.Next()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return fmt.Errorf("extractTarGz() tarReader.Next() Error %v", err.Error())
		case header == nil:
			continue
		}
		target := filepath.Join(targetDir, header.Name)
		switch header.Typeflag {

		case tar.TypeReg:
			dirPath := filepath.Dir(target)
			err = os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("extractTarGz() os.MkdirAll(%v) Error L.40 %v", dirPath, err.Error())
			}
			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("extractTarGz() os.Create(%v) L.47 Error %v", target, err.Error())
			}
			defer func(outFile *os.File) {
				err := outFile.Close()
				if err != nil {

				}
			}(outFile)
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return fmt.Errorf("extractTarGz() io.Copy Error %v", target, err.Error())
			}
			_ = outFile.Close()
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.ModePerm); err != nil {
				return fmt.Errorf("extractTarGz() os.MkdirAll(%v) Error L.54 %v", target, err.Error())
			}
		}
	}
}
func extractTar(tarStream io.Reader, targetDir string) error {
	tarReader := tar.NewReader(tarStream)

	for {
		header, err := tarReader.Next()
		switch {
		case err == io.EOF:
			return nil // End of archive
		case err != nil:
			return fmt.Errorf("extractTar(): tarReader.Next() error: %v", err)
		case header == nil:
			continue
		}

		target := filepath.Join(targetDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.ModePerm); err != nil {
				return fmt.Errorf("extractTar(): os.MkdirAll(%v) error: %v", target, err)
			}
		case tar.TypeReg:
			dirPath := filepath.Dir(target)
			if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
				return fmt.Errorf("extractTar(): os.MkdirAll(%v) error: %v", dirPath, err)
			}

			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("extractTar(): os.Create(%v) error: %v", target, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				_ = outFile.Close()
				return fmt.Errorf("extractTar(): io.Copy(%v) error: %v", target, err)
			}

			if err := outFile.Close(); err != nil {
				return fmt.Errorf("extractTar(): closing file %v error: %v", target, err)
			}
		}
	}
}
func ExtractTarGzSingle(FileSource string, pattern string, DestDir string) error {

	if !fileExists(FileSource) {
		return fmt.Errorf(FileSource, "No such file")
	}

	gzipStream, err := os.Open(FileSource)
	if err != nil {
		return fmt.Errorf("ExtractTarGzSingle Failed to open file:", FileSource, err)

	}
	defer func() {
		closeErr := gzipStream.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	tarReader := tar.NewReader(uncompressedStream)

	for true {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed reading tar entry header: %v", err)
		}

		target := filepath.Join(DestDir, filepath.Base(header.Name))
		patternRe := regexp.MustCompile(pattern)
		if !patternRe.MatchString(header.Name) {
			log.Debug().Msg(fmt.Sprintf("LinuxExtractTarGzSingle: %v no matches %v", header.Name, pattern))
			continue
		}

		log.Debug().Msg(fmt.Sprintf("LinuxExtractTarGzSingle: [%v] matches [%v]", header.Name, pattern))

		switch header.Typeflag {
		case tar.TypeDir:
			log.Debug().Msg(fmt.Sprintf("LinuxExtractTarGzSingle: %v is ad directory, SKIP", header.Name))
			continue
		case tar.TypeReg:
			log.Debug().Msg(fmt.Sprintf("LinuxExtractTarGzSingle: Extracting %v ", target))
			file, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %v", target, err)
			}
			if _, err := io.Copy(file, tarReader); err != nil {
				_ = file.Close()
				return fmt.Errorf("failed to copy contents to file %s: %v", target, err)
			}
			_ = file.Close()
		}
	}
	return nil

}
func IsTarGz(filename string) bool {

	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	magic := make([]byte, 2)
	_, err = file.Read(magic)
	if err != nil {
		return false
	}
	if !bytes.Equal(magic, []byte{0x1F, 0x8B}) {
		return false
	}

	_, _ = file.Seek(0, 0)
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return false // Not a valid gzip
	}
	defer func(gzReader *gzip.Reader) {
		_ = gzReader.Close()
	}(gzReader)

	return true // File is a valid .tar.gz
}

func UntarTgz(SrcFile string, DestDir string) error {
	if !fileExists(SrcFile) {

		return fmt.Errorf("UntarTgz(): os.open(%v) %v", SrcFile, "No such file")

	}
	log.Warn().Msgf("%v EXTTGZ Extract %v -> %v", getCalleRuntime(), SrcFile, DestDir)
	Format, _ := DetectFormat(SrcFile)
	tarball, err := os.Open(SrcFile)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v os.Open() %v format=%v", SrcFile, err, Format))
	}
	defer func(tarball *os.File) {
		_ = tarball.Close()
	}(tarball)

	if Format == "tar" {
		if err := extractTar(tarball, DestDir); err != nil {
			return fmt.Errorf("%v format=%v error %v", getCalleRuntime(), Format, err.Error())
		}
		return nil
	}

	if err := extractTarGz(tarball, DestDir); err != nil {
		return fmt.Errorf("%v format=%v error %v", getCalleRuntime(), Format, err.Error())
	}
	return nil
}

func CompressZIP(zipPath string, files []string) error {
	// Create the ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer func(zipFile *os.File) {
		err := zipFile.Close()
		if err != nil {

		}
	}(zipFile)

	// Create a new ZIP writer
	zipWriter := zip.NewWriter(zipFile)
	defer func(zipWriter *zip.Writer) {
		err := zipWriter.Close()
		if err != nil {

		}
	}(zipWriter)

	for _, file := range files {
		err := addFileToZip(zipWriter, file)
		if err != nil {
			return err
		}
	}

	return nil
}
func addFileToZip(zipWriter *zip.Writer, filename string) error {
	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func(fileToZip *os.File) {
		err := fileToZip.Close()
		if err != nil {

		}
	}(fileToZip)
	fileInfo, err := fileToZip.Stat()
	if err != nil {
		return err
	}
	header, err := zip.FileInfoHeader(fileInfo)
	if err != nil {
		return err
	}
	header.Name = filepath.Base(filename)
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, fileToZip)
	return err
}
func CompressGZ(sourceFilePath string, destinationFilePath string) error {

	sourceFile, err := os.Open(sourceFilePath)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v os.Open() %v", sourceFile, err))
	}
	defer sourceFile.Close()
	destinationFile, err := os.Create(destinationFilePath)
	if err != nil {
		return err
	}
	defer destinationFile.Close()
	gzipWriter := gzip.NewWriter(destinationFile)
	defer gzipWriter.Close()
	_, err = io.Copy(gzipWriter, sourceFile)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("gzipWriter io.Copy() Error %v", sourceFile, err))
	}

	err = gzipWriter.Close()
	if err != nil {
		return err
	}
	return nil
}
func copyFile(Source string, destination string) error {

	if !fileExists(Source) {
		return errors.New(fmt.Sprintf("%v No such file", Source))
	}

	srcFile, err := os.Open(Source)
	if err != nil {
		return errors.New(fmt.Sprintf("%v Open failed %v", Source, err.Error()))

	}

	defer func(srcFile *os.File) {
		_ = srcFile.Close()
	}(srcFile)

	if fileExists(destination) {
		err = os.Remove(destination)
		if err != nil {
			return errors.New(fmt.Sprintf("%v remove failed %v", destination, err.Error()))

		}
	}
	// Create the destination file for writing
	destFile, err := os.Create(destination)
	if err != nil {
		return errors.New(fmt.Sprintf("%v Create failed %v", destination, err.Error()))
	}
	defer func(destFile *os.File) {
		_ = destFile.Close()
	}(destFile)

	// Copy the contents from source to destination
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return errors.New(fmt.Sprintf("%v Copy failed %v", destination, err.Error()))
	}
	return nil
}

type FileType string

const (
	FileTypeGzip  FileType = "gzip"
	FileTypeText  FileType = "text"
	FileTypeOther FileType = "other"
)

func IsTextFile(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	// Read first 512 bytes (magic + text detection)
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil {
		return false
	}
	buf = buf[:n]

	// Check for GZIP magic header
	if len(buf) >= 2 && buf[0] == 0x1f && buf[1] == 0x8b {
		return false
	}

	// Check if mostly printable characters (simple heuristic)
	printable := 0
	for _, b := range buf {
		if b == 0 || (!unicode.IsPrint(rune(b)) && !unicode.IsSpace(rune(b))) {
			continue
		}
		printable++
	}

	if float64(printable)/float64(len(buf)) > 0.9 {
		return true
	}

	return false
}

func IsGZ(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	// Read first 512 bytes (magic + text detection)
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil {
		return false
	}
	buf = buf[:n]

	// Check for GZIP magic header
	if len(buf) >= 2 && buf[0] == 0x1f && buf[1] == 0x8b {
		return true
	}

	// Check if mostly printable characters (simple heuristic)
	printable := 0
	for _, b := range buf {
		if b == 0 || (!unicode.IsPrint(rune(b)) && !unicode.IsSpace(rune(b))) {
			continue
		}
		printable++
	}

	if float64(printable)/float64(len(buf)) > 0.9 {
		// Is a Text file
		return false
	}

	return false
}
func unCompressGZFallback(gzFilePath, outputFilePath string) error {
	gunzip := "/usr/bin/gunzip"
	if !fileExists(gunzip) {
		return fmt.Errorf("%v not found", gunzip)
	}

	cmd := exec.Command(gunzip, "-c", gzFilePath)
	outFile, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("unCompressGZFallback() %v os.Create() %v", outputFilePath, err)
	}
	defer func(outFile *os.File) {
		_ = outFile.Close()
	}(outFile)

	cmd.Stdout = outFile
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("unCompressGZFallback() %v Run() %v", outputFilePath, err)
	}
	return nil
}

func unCompressGZSmart(gzFilePath, outputFilePath string) error {
	data, err := os.ReadFile(gzFilePath)
	if err != nil {
		return err
	}

	magic := []byte{0x1f, 0x8b}
	index := bytes.Index(data, magic)
	if index == -1 {
		return unCompressGZFallback(gzFilePath, outputFilePath)
	}

	buf := bytes.NewReader(data[index:])
	gzReader, err := gzip.NewReader(buf)
	if err != nil {
		return err
	}
	defer func(gzReader *gzip.Reader) {
		_ = gzReader.Close()
	}(gzReader)

	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer func(outputFile *os.File) {
		_ = outputFile.Close()
	}(outputFile)

	_, err = io.Copy(outputFile, gzReader)
	return err
}
func UnCompressGZ(gzFilePath string, outputFilePath string) error {

	gzFile, err := os.Open(gzFilePath)
	if err != nil {
		return fmt.Errorf("UnCompressGZ os.Open() %v", err)
	}
	defer func(gzFile *os.File) {
		_ = gzFile.Close()
	}(gzFile)

	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		return unCompressGZSmart(gzFilePath, outputFilePath)
	}
	defer func(gzReader *gzip.Reader) {
		_ = gzReader.Close()
	}(gzReader)

	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer func(outputFile *os.File) {
		_ = outputFile.Close()
	}(outputFile)

	if _, err = io.Copy(outputFile, gzReader); err != nil {
		return err
	}

	return nil
}

func ZipFile(ZipFilePath string, FileToCompress string) error {

	zipFile, err := os.Create(ZipFilePath)
	if err != nil {
		return err
	}
	defer zipFile.Close()
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	fileToZip, err := os.Open(FileToCompress)
	if err != nil {
		return err
	}
	defer fileToZip.Close()

	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, fileToZip)
	return err

}

func UnzipFile(ZipFilePath string, TargetDirectory string) error {

	if !fileExists(ZipFilePath) {
		return errors.New(fmt.Sprintf("%v No such zip file", ZipFilePath))
	}

	r, err := zip.OpenReader(ZipFilePath)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to open zip with error %v", err.Error()))
	}
	defer func() {
		closeErr := r.Close()
		if closeErr != nil {
			log.Error().Msg(fmt.Sprintf("compressor.UnzipFile: r.close() error %v", closeErr.Error()))
		}
	}()

	for _, f := range r.File {
		fpath := filepath.Join(TargetDirectory, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(TargetDirectory)+string(os.PathSeparator)) {
			return errors.New(fmt.Sprintf("Illegal file path: %v", fpath))
		}

		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(fpath, os.ModePerm)
		} else {
			TDir := filepath.Dir(fpath)
			if err := os.MkdirAll(TDir, os.ModePerm); err != nil {
				return errors.New(fmt.Sprintf("Failed to create directory %v with error %v", TDir, err.Error()))
			}

			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to open output file %v with error %v", fpath, err.Error()))
			}

			rc, err := f.Open()
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to open zip file with error %v", err.Error()))
			}

			_, err = io.Copy(outFile, rc)
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to copy data to file with error %v", err.Error()))
			}

			_ = outFile.Close()
			_ = rc.Close()
		}
	}
	return nil
}
func fileExists(spath string) bool {
	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
func CompressDirectoyShell(srcDir, destFile string) error {
	log.Warn().Msgf("%v EXTTGZ Compress %v -> %v", getCalleRuntime(), srcDir, destFile)
	var f []string
	if !isDirDirectory(srcDir) {
		return fmt.Errorf("%v isn't a directory", srcDir)
	}
	Tmpfile := tempFileName()
	f = append(f, "#!/usr/bin/env bash")
	tarBin := "/usr/bin/tar"
	f = append(f, fmt.Sprintf("cd %v", srcDir))
	f = append(f, fmt.Sprintf("%v --no-recursion -czf %v -C %v *", tarBin, destFile, srcDir))
	f = append(f, fmt.Sprintf("rm -f %v", Tmpfile))
	f = append(f, "")
	_ = filePutContents(Tmpfile, strings.Join(f, "\n"))
	chmod(Tmpfile, 0755)
	err, out := executeShell(Tmpfile)
	if err != nil {
		return fmt.Errorf("%v %v", getCalleRuntime(), out)

	}
	return nil
}
func filePutContents(filename string, data string) error {
	filename = strings.TrimSpace(filename)
	return os.WriteFile(filename, []byte(data), 0644)
}
func tempFileName() string {
	tempDir := tempDir()
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%s/tempfile_%d.tmp", tempDir, timestamp)
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
func tempDir() string {
	SysTmpDir := sockets.GET_INFO_STR("SysTmpDir")
	if len(SysTmpDir) < 4 {
		_ = os.MkdirAll("/home/artica/tmp", 0755)
		return "/home/artica/tmp"
	}
	if SysTmpDir == "/tmp" {
		return os.TempDir()
	}
	_ = os.MkdirAll(SysTmpDir, 0755)
	return SysTmpDir
}
func CompressDirectoy(srcDir, destFile string) error {
	outFile, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	gzipWriter := gzip.NewWriter(outFile)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	err = filepath.Walk(srcDir, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		header.Name = file
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		fileHandle, err := os.Open(file)
		if err != nil {
			return err
		}
		defer fileHandle.Close()
		_, err = io.Copy(tarWriter, fileHandle)
		return err
	})

	return err
}

func CompressDirectoyStrip(srcDir, destFile string, DeleteRoot string) error {
	outFile, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	gzipWriter := gzip.NewWriter(outFile)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	log.Debug().Msg(fmt.Sprintf("%v Compress: filepath.Walk(%v) to %v Remove=%v", getCalleRuntime(), srcDir, destFile, DeleteRoot))

	err = filepath.Walk(srcDir, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			log.Debug().Msg(fmt.Sprintf("%v Compress: filepath.Walk ERROR--> %v", getCalleRuntime(), err.Error()))
			return err
		}
		if file == destFile {
			return nil
		}

		header, err := tar.FileInfoHeader(fi, "")

		if err != nil {
			log.Debug().Msg(fmt.Sprintf("%v Compress:  tar.FileInfoHeader(fi ERROR--> %v", getCalleRuntime(), err.Error()))
			return err
		}
		header.Name = strings.TrimPrefix(strings.Replace(file, DeleteRoot, "", -1), string(filepath.Separator))
		if err := tarWriter.WriteHeader(header); err != nil {
			log.Debug().Msg(fmt.Sprintf("%v Compress:  tarWriter.WriteHeader(header); --> %v --> %v [%v]", getCalleRuntime(), file, header.Name, err.Error()))
			return fmt.Errorf(fmt.Sprintf("%v %v", file, err))
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		fileHandle, err := os.Open(file)
		if err != nil {
			log.Debug().Msg(fmt.Sprintf("%v Compress:  os.Open(%v) %v", getCalleRuntime(), file, err.Error()))
			return err
		}
		defer fileHandle.Close()
		_, err = io.Copy(tarWriter, fileHandle)
		if err != nil {
			log.Debug().Msg(fmt.Sprintf("%v Compress:  io.Copy(tarWriter)  %v %v", getCalleRuntime(), file, err.Error()))
		}
		return err
	})

	return err
}
func ReadFirstLinesGz(filePath string, numLines int) []string {
	var lines []string
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Msgf("%v %v %v", getCalleRuntime(), filePath, err)
		return lines
	}
	defer file.Close()
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		log.Error().Msgf("%v %v %v", getCalleRuntime(), filePath, err)
		return lines
	}
	defer gzReader.Close()
	reader := bufio.NewReader(gzReader)

	for i := 0; i < numLines; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Error().Msgf("%v %v %v", getCalleRuntime(), filePath, err)
			return lines
		}
		lines = append(lines, line)
	}

	return lines
}
func ReadLastLinesGz(filePath string, numLines int) []string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Msgf("%v %v %v", getCalleRuntime(), filePath, err)
		return []string{}
	}
	defer file.Close()
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		log.Error().Msgf("%v %v %v", getCalleRuntime(), filePath, err)
		return []string{}
	}
	defer gzReader.Close()
	reader := bufio.NewReader(gzReader)
	lines := make([]string, 0, numLines)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Error().Msgf("%v %v %v", getCalleRuntime(), filePath, err)
			return lines
		}

		if len(lines) < numLines {
			lines = append(lines, line)
		} else {
			copy(lines, lines[1:])
			lines[numLines-1] = line
		}
	}

	return lines
}
func chmod(TargetPath string, desiredMode os.FileMode) {
	if !fileExists(TargetPath) {
		return
	}
	_ = os.Chmod(TargetPath, desiredMode)
}
func executeShell(CommandLine string) (error, string) {
	shbin := "/usr/bin/sh"
	cmd := exec.Command(shbin, "-c", CommandLine)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return err, string(output)
	}
	return nil, string(output)
}
func getCalleRuntime() string {
	if pc, file, line, ok := runtime.Caller(1); ok {
		file = file[strings.LastIndex(file, "/")+1:]
		funcName := runtime.FuncForPC(pc).Name()
		funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
		funcName = strings.ReplaceAll(funcName, "articarest/dnsdist/", "")

		return fmt.Sprintf("%s[%s:%d]", file, funcName, line)
	}
	return ""
}
