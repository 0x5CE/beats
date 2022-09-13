// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Code generated by beats/dev-tools/cmd/asset/asset.go - DO NOT EDIT.

package beat

import (
	"github.com/elastic/beats/v7/libbeat/asset"
)

func init() {
	if err := asset.SetFields("metricbeat", "beat", asset.ModuleFieldsPri, AssetBeat); err != nil {
		panic(err)
	}
}

// AssetBeat returns asset data.
// This is the base64 encoded zlib format compressed contents of module/beat.
func AssetBeat() string {
	return "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"
}
