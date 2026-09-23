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

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

// localUploader satisfies pipeline.Uploader by writing objects to a local
// directory instead of S3, mirroring the S3 key as a relative file path.
// Used by `publish -output-dir` to let an operator inspect the produced
// bundle/SBOM/VEX files without touching the (immutable) catalog bucket.
type localUploader struct {
	dir string
}

func (u *localUploader) Upload(_ context.Context, key string, data io.Reader, _ string) (bool, error) {
	path := filepath.Join(u.dir, key)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}

	f, err := os.Create(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, data); err != nil {
		return false, err
	}
	return false, nil
}
