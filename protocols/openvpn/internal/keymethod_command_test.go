package openvpn

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadCommandRejectsOversizeWithoutTerminator(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 128)), 16)
	if _, err := ReadCommand(reader, 32); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("error = %v, want size limit before EOF", err)
	}
}

func TestReadCommandAcrossBuffers(t *testing.T) {
	want := strings.Repeat("x", 100)
	reader := bufio.NewReaderSize(strings.NewReader(want+"\x00INFO\x00"), 16)
	command, err := ReadCommand(reader, 128)
	if err != nil || command != want {
		t.Fatalf("command = %q, error = %v", command, err)
	}
	command, err = ReadCommand(reader, 128)
	if err != nil || command != "INFO" {
		t.Fatalf("next command = %q, error = %v", command, err)
	}
}
