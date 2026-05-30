package log

import (
	"fmt"
	"io"
)

type Logger struct {
	Writer  io.Writer
	Verbose bool
}

func (l Logger) Debugf(format string, args ...any) {
	if l.Verbose && l.Writer != nil {
		fmt.Fprintf(l.Writer, format+"\n", args...)
	}
}
