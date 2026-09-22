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
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// s3Client is the subset of *s3.Client used by Uploader, extracted as an
// interface for testability (real AWS calls are not appropriate in unit tests).
type s3Client interface {
	HeadObject(ctx context.Context, input *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(ctx context.Context, input *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// Uploader uploads objects to a single S3 bucket, skipping any object that
// already exists (bucket is immutable; this makes re-runs/retries safe).
type Uploader struct {
	client s3Client
	bucket string
}

// NewUploader builds an Uploader for the given bucket/region using the
// default AWS SDK v2 credential chain (env, shared config, IAM role/SSO
// profile) -- never accept credentials via this tool's own config file.
func NewUploader(ctx context.Context, bucket, region string) (*Uploader, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg)
	return &Uploader{client: client, bucket: bucket}, nil
}

// Upload puts data at key in the bucket, unless an object already exists at
// that key (checked via HeadObject first), in which case it returns
// (skipped=true, err=nil) and does NOT attempt the PUT. Returns
// (skipped=false, err=nil) on a successful upload.
func (u *Uploader) Upload(ctx context.Context, key string, data io.Reader, contentType string) (skipped bool, err error) {
	_, err = u.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		return true, nil
	}

	var notFound *types.NotFound
	if !errors.As(err, &notFound) {
		return false, err
	}

	bodyBytes, err := io.ReadAll(data)
	if err != nil {
		return false, err
	}

	_, err = u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(u.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(bodyBytes),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return false, err
	}

	return false, nil
}
