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

package model

import "testing"

func TestComponent_FindAssetBySuffix(t *testing.T) {
	comp := Component{
		Assets: []Asset{
			{Filename: "jackson-core-2.13.5.1-osera-00001.jar"},
			{Filename: "jackson-core-2.13.5.1-osera-00001.pom"},
			{Filename: "jackson-core-2.13.5.1-osera-00001-cyclonedx.json"},
		},
	}

	t.Run("found", func(t *testing.T) {
		asset, ok := comp.FindAssetBySuffix("-cyclonedx.json")
		if !ok {
			t.Fatal("expected to find asset")
		}
		if asset.Filename != "jackson-core-2.13.5.1-osera-00001-cyclonedx.json" {
			t.Errorf("Filename = %q", asset.Filename)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, ok := comp.FindAssetBySuffix("-sources.jar")
		if ok {
			t.Fatal("expected not to find asset")
		}
	})

	t.Run("suffix longer than filename", func(t *testing.T) {
		_, ok := comp.FindAssetBySuffix("this-suffix-is-way-too-long-to-match-anything.json")
		if ok {
			t.Fatal("expected not to find asset for over-long suffix")
		}
	})

	t.Run("empty assets", func(t *testing.T) {
		empty := Component{}
		_, ok := empty.FindAssetBySuffix(".jar")
		if ok {
			t.Fatal("expected not to find asset in empty component")
		}
	})
}
