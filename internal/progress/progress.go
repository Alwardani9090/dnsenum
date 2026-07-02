package progress

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const toolProgressPrefix = "DNSENUM_PROGRESS"

// ToolProgressEnabled reports whether machine-readable progress output is
// enabled via the DNSENUM_PROGRESS environment variable. This is meant for
// tools that want to wrap dnsenum and parse its progress in real time.
func ToolProgressEnabled() bool {
	return os.Getenv("DNSENUM_PROGRESS") == "1"
}

// WriteToolProgress writes a single machine-readable progress line to w.
// It is a no-op unless ToolProgressEnabled() is true.
func WriteToolProgress(w io.Writer, done, total int, label string) {
	if !ToolProgressEnabled() || w == nil || total <= 0 {
		return
	}

	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}

	label = strings.ReplaceAll(label, "\n", " ")
	label = strings.ReplaceAll(label, "\r", " ")
	fmt.Fprintf(w, "%s\t%d\t%d\t%s\n", toolProgressPrefix, done, total, label)
}

// ParseToolProgressLine parses a line previously written by WriteToolProgress.
func ParseToolProgressLine(line string) (done, total int, label string, ok bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, toolProgressPrefix+"\t") {
		return 0, 0, "", false
	}

	parts := strings.SplitN(line, "\t", 4)
	if len(parts) < 4 {
		return 0, 0, "", false
	}

	done, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, "", false
	}
	total, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, "", false
	}
	label = parts[3]
	return done, total, label, total > 0
}
