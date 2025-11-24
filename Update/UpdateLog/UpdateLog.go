package UpdateLog

import (
	"bufio"
	"fmt"
	"futils"
	"os"
)

func UpdateEvent(text, function string) {
	LineStr := fmt.Sprintf("%s [%s] %s\n",
		futils.TimeStampToString(),
		function,
		text,
	)
	file, err := os.OpenFile("/var/log/suricata-update.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	if err != nil {
		return
	}
	writer := bufio.NewWriterSize(file, 4096)
	defer func(writer *bufio.Writer) {
		_ = writer.Flush()
	}(writer)
	_, _ = writer.WriteString(LineStr)
}
