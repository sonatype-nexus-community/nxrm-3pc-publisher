/**
 * Copyright (c) 2019-present Sonatype, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{"error", slog.LevelError, false},
		{"ERROR", slog.LevelError, false},
		{"warn", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"Warning", slog.LevelWarn, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{"trace", LevelTrace, false},
		{"Trace", LevelTrace, false},
		{"debug", 0, true},
		{"", 0, true},
		{"bogus", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseLevel(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNew_levelFiltering(t *testing.T) {
	logger := New(slog.LevelWarn, "text", &bytes.Buffer{})

	if logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected INFO to be disabled when configured at WARN")
	}
	if !logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("expected WARN to be enabled when configured at WARN")
	}
	if !logger.Enabled(context.Background(), slog.LevelError) {
		t.Error("expected ERROR to be enabled when configured at WARN")
	}
}

func TestNew_traceLevelEnabled(t *testing.T) {
	logger := New(LevelTrace, "text", &bytes.Buffer{})

	if !logger.Enabled(context.Background(), LevelTrace) {
		t.Error("expected TRACE to be enabled when configured at TRACE")
	}
}

func TestNew_traceRendersAsTraceNotDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelTrace, "text", &buf)

	logger.Log(context.Background(), LevelTrace, "a trace message")

	out := buf.String()
	if !strings.Contains(out, "TRACE") {
		t.Errorf("expected output to contain %q, got %q", "TRACE", out)
	}
	if strings.Contains(out, "DEBUG") {
		t.Errorf("expected output not to contain %q, got %q", "DEBUG", out)
	}
}

func TestNew_textFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(slog.LevelInfo, "text", &buf)

	logger.Info("hello", "count", 3)

	out := buf.String()
	if !strings.Contains(out, "msg=hello") {
		t.Errorf("expected text output to contain %q, got %q", "msg=hello", out)
	}
	if !strings.Contains(out, "count=3") {
		t.Errorf("expected text output to contain %q, got %q", "count=3", out)
	}
}

func TestNew_jsonFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(slog.LevelInfo, "json", &buf)

	logger.Info("hello", "count", 3)

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v (output: %q)", err, buf.String())
	}
	if decoded["msg"] != "hello" {
		t.Errorf("decoded[msg] = %v, want %q", decoded["msg"], "hello")
	}
	if decoded["count"] != float64(3) {
		t.Errorf("decoded[count] = %v, want 3", decoded["count"])
	}
}

func TestNew_jsonFormatCaseInsensitive(t *testing.T) {
	var buf bytes.Buffer
	logger := New(slog.LevelInfo, "JSON", &buf)

	logger.Info("hello")

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("expected valid JSON output with format=JSON, got error: %v", err)
	}
}
