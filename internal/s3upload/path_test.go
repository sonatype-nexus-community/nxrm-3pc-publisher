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

package s3upload

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/config"
	"github.com/sonatype-nexus-community/nxrm-3pc-publisher/internal/model"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestBundlePath(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		namespace string
		pkgName   string
		version   string
		want      string
	}{
		{
			name:      "Maven with namespace",
			ecosystem: "maven",
			namespace: "org.springframework.boot",
			pkgName:   "spring-boot",
			version:   "4.1.1-patched-1",
			want:      "packages/maven/org.springframework.boot/spring-boot/4.1.1-patched-1/spring-boot-4.1.1-patched-1.zip",
		},
		{
			name:      "npm without namespace",
			ecosystem: "npm",
			namespace: "",
			pkgName:   "react",
			version:   "19.2.8-patched-1",
			want:      "packages/npm/react/19.2.8-patched-1/react-19.2.8-patched-1.zip",
		},
		{
			name:      "npm with namespace/scope",
			ecosystem: "npm",
			namespace: "@babel",
			pkgName:   "core",
			version:   "7.26.0-patched-1",
			want:      "packages/npm/@babel/core/7.26.0-patched-1/core-7.26.0-patched-1.zip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BundlePath(tt.ecosystem, tt.namespace, tt.pkgName, tt.version)
			if got != tt.want {
				t.Errorf("BundlePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVEXPath(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{
			name:     "CVE-based VEX",
			filename: "CVE-2024-12345-2024-01-15.bom.json",
			want:     "vex/CVE-2024-12345-2024-01-15.bom.json",
		},
		{
			name:     "timestamp-based VEX",
			filename: "2024-01-15T10-30-00Z.bom.json",
			want:     "vex/2024-01-15T10-30-00Z.bom.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VEXPath(tt.filename)
			if got != tt.want {
				t.Errorf("VEXPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNamespace(t *testing.T) {
	tests := []struct {
		name    string
		comp    model.Component
		repoCfg config.Repository
		want    string
	}{
		{
			name: "NamespaceFromGroup true with group",
			comp: model.Component{
				Group: "org.springframework.boot",
			},
			repoCfg: config.Repository{
				NamespaceFromGroup: true,
			},
			want: "org.springframework.boot",
		},
		{
			name: "NamespaceFromGroup true but group empty",
			comp: model.Component{
				Group: "",
			},
			repoCfg: config.Repository{
				NamespaceFromGroup: true,
			},
			want: "",
		},
		{
			name: "NamespaceFromGroup false with group",
			comp: model.Component{
				Group: "com.fasterxml.jackson.core",
			},
			repoCfg: config.Repository{
				NamespaceFromGroup: false,
			},
			want: "",
		},
		{
			name: "NamespaceFromGroup false and group empty",
			comp: model.Component{
				Group: "",
			},
			repoCfg: config.Repository{
				NamespaceFromGroup: false,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Namespace(tt.comp, tt.repoCfg)
			if got != tt.want {
				t.Errorf("Namespace() = %q, want %q", got, tt.want)
			}
		})
	}
}

type mockS3Client struct {
	headObjectFunc func(ctx context.Context, input *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	putObjectFunc  func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func (m *mockS3Client) HeadObject(ctx context.Context, input *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if m.headObjectFunc == nil {
		return nil, errors.New("HeadObject not implemented")
	}
	return m.headObjectFunc(ctx, input, opts...)
}

func (m *mockS3Client) PutObject(ctx context.Context, input *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putObjectFunc == nil {
		return nil, errors.New("PutObject not implemented")
	}
	return m.putObjectFunc(ctx, input, opts...)
}

func TestUpload(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		data          string
		contentType   string
		headObjectErr error
		putObjectErr  error
		wantSkipped   bool
		wantErr       bool
		errContains   string
	}{
		{
			name:          "object exists - skip",
			key:           "packages/maven/test/test/1.0.0/test-1.0.0.zip",
			data:          "test data",
			contentType:   "application/zip",
			headObjectErr: nil,
			wantSkipped:   true,
			wantErr:       false,
		},
		{
			name:        "object not found - upload",
			key:         "packages/maven/test/test/1.0.0/test-1.0.0.zip",
			data:        "test data",
			contentType: "application/zip",
			headObjectErr: &types.NotFound{
				Message: aws.String("Not Found"),
			},
			wantSkipped: false,
			wantErr:     false,
		},
		{
			name:          "unexpected HeadObject error - propagate",
			key:           "packages/maven/test/test/1.0.0/test-1.0.0.zip",
			data:          "test data",
			contentType:   "application/zip",
			headObjectErr: errors.New("network error"),
			wantSkipped:   false,
			wantErr:       true,
			errContains:   "network error",
		},
		{
			name:        "object not found but PutObject fails - propagate",
			key:         "packages/maven/test/test/1.0.0/test-1.0.0.zip",
			data:        "test data",
			contentType: "application/zip",
			headObjectErr: &types.NotFound{
				Message: aws.String("Not Found"),
			},
			putObjectErr: errors.New("upload failed"),
			wantSkipped:  false,
			wantErr:      true,
			errContains:  "upload failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockS3Client{
				headObjectFunc: func(ctx context.Context, input *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
					if tt.headObjectErr != nil {
						return nil, tt.headObjectErr
					}
					return &s3.HeadObjectOutput{}, nil
				},
				putObjectFunc: func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
					if tt.putObjectErr != nil {
						return nil, tt.putObjectErr
					}
					if input.Bucket == nil || *input.Bucket != "test-bucket" {
						t.Errorf("PutObject bucket = %v, want test-bucket", input.Bucket)
					}
					if input.Key == nil || *input.Key != tt.key {
						t.Errorf("PutObject key = %v, want %s", input.Key, tt.key)
					}
					if input.ContentType == nil || *input.ContentType != tt.contentType {
						t.Errorf("PutObject content type = %v, want %s", input.ContentType, tt.contentType)
					}
					return &s3.PutObjectOutput{}, nil
				},
			}

			uploader := &Uploader{
				client: mock,
				bucket: "test-bucket",
				logger: discardLogger(),
			}

			skipped, err := uploader.Upload(context.Background(), tt.key, strings.NewReader(tt.data), tt.contentType)

			if skipped != tt.wantSkipped {
				t.Errorf("Upload() skipped = %v, want %v", skipped, tt.wantSkipped)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Upload() err = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Upload() err = %v, want error containing %q", err, tt.errContains)
			}
		})
	}
}

func TestNewUploader(t *testing.T) {
	// We can't test this with a real AWS config in this environment, but we can
	// verify that the constructor exists and has the right signature.
	t.Skip("NewUploader requires AWS credentials which are not available in test environment")
}

func TestUploadReadsEntireReader(t *testing.T) {
	mock := &mockS3Client{
		headObjectFunc: func(ctx context.Context, input *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
			return nil, &types.NotFound{Message: aws.String("Not Found")}
		},
		putObjectFunc: func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
			body, err := io.ReadAll(input.Body)
			if err != nil {
				t.Errorf("Failed to read body: %v", err)
			}
			if string(body) != "test content for reader" {
				t.Errorf("PutObject body = %q, want %q", string(body), "test content for reader")
			}
			return &s3.PutObjectOutput{}, nil
		},
	}

	uploader := &Uploader{
		client: mock,
		bucket: "test-bucket",
		logger: discardLogger(),
	}

	data := strings.NewReader("test content for reader")
	skipped, err := uploader.Upload(context.Background(), "test-key", data, "application/octet-stream")

	if skipped {
		t.Error("Upload() skipped = true, want false")
	}
	if err != nil {
		t.Errorf("Upload() err = %v, want nil", err)
	}
}
