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

//go:build !integration
// +build !integration

package mssql

import (
	"encoding/hex"
	"testing"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/publish"
)

type eventStore struct {
	events []beat.Event
}

func (e *eventStore) publish(event beat.Event) {
	publish.MarshalPacketbeatFields(&event, nil, nil)
	e.events = append(e.events, event)
}

func mssqlModForTests(store *eventStore) *mssqlPlugin {
	callback := func(beat.Event) {}
	if store != nil {
		callback = store.publish
	}

	var mssql mssqlPlugin
	config := defaultConfig
	mssql.init(callback, procs.ProcessesWatcher{}, &config)
	return &mssql
}

func TestMssqlParser_16x_insertQuery(t *testing.T) {
	mssql := mssqlModForTests(nil)

	data := []byte(
		"010100820000010016000000120000000200000000000000000001" +
			"00000049004e005300450052005400200049004e0054004f00200049" +
			"006e00760065006e0074006f00720079002000560041004c005500450" +
			"053002000280033002c00200027006f00720061006e0067006500610027002" +
			"c00200031003100310029003b000a00")

	message, err := hex.DecodeString(string(data))
	if err != nil {
		t.Error("Failed to decode hex string")
	}

	stream := &mssqlStream{data: message, message: new(mssqlMessage)}

	ok, complete := mssql.mssqlMessageParser(stream)

	if !ok {
		t.Error("Parsing returned error")
	}
	if !complete {
		t.Error("Expecting a complete message")
	}
	if !stream.message.isRequest {
		t.Error("Failed to parse MSSQL request")
	}
	if stream.message.query != "INSERT INTO Inventory VALUES (3, 'orangea', 111);" {
		t.Error("Failed to parse query")
	}
	if stream.message.size != 130 {
		t.Errorf("Wrong message size %d", stream.message.size)
	}
}

func TestMssqlParser_16x_selectResponse(t *testing.T) {
	mssql := mssqlModForTests(nil)

	data := []byte("0401006e003501008103000000000009002604026900640000" +
		"0000000900e764000904d00034046e0061006d006500000000000900260408" +
		"7100750061006e007400690074007900d104020000000c006f00720061006e" +
		"0067006500049a000000fd1000c1000100000000000000")

	message, err := hex.DecodeString(string(data))
	if err != nil {
		t.Error("Failed to decode hex string")
	}

	stream := &mssqlStream{data: message, message: new(mssqlMessage)}

	ok, complete := mssql.mssqlMessageParser(stream)

	if !ok {
		t.Error("Parsing returned error")
	}
	if !complete {
		t.Error("Expecting a complete message")
	}
	if stream.message.isRequest {
		t.Error("Failed to parse MSSQL response")
	}
	if stream.message.size != 110 {
		t.Errorf("Wrong message size %d", stream.message.size)
	}

	// parse fields and rows
	raw := stream.data[stream.message.start:stream.message.end]
	if len(raw) == 0 {
		t.Errorf("Empty raw data")
	}
	fields, rows := parseQueryResponse(raw)
	if len(fields) != 3 {
		t.Errorf("Wrong number of fields")
	}
	if len(rows) != 1 {
		t.Errorf("Wrong number of rows")
	}
	if len(rows[0]) != 3 {
		t.Errorf("Wrong number of columns")
	}
}

func TestMssqlParser_16x_datetimeResponse(t *testing.T) {
	mssql := mssqlModForTests(nil)

	data := []byte("04010049003501008102000000000009" +
		"00260402690064000000000008003d07" +
		"6300720065006100740065006400d104" +
		"20000000eaae0000a2745901fd1000c1" +
		"000100000000000000")

	message, err := hex.DecodeString(string(data))
	if err != nil {
		t.Error("Failed to decode hex string")
	}

	stream := &mssqlStream{data: message, message: new(mssqlMessage)}

	ok, complete := mssql.mssqlMessageParser(stream)

	if !ok {
		t.Error("Parsing returned error")
	}
	if !complete {
		t.Error("Expecting a complete message")
	}
	if stream.message.isRequest {
		t.Error("Failed to parse MSSQL response")
	}
	if stream.message.size != 73 {
		t.Errorf("Wrong message size %d", stream.message.size)
	}

	// parse fields and rows
	raw := stream.data[stream.message.start:stream.message.end]
	if len(raw) == 0 {
		t.Errorf("Empty raw data")
	}
	fields, rows := parseQueryResponse(raw)
	if len(fields) != 2 {
		t.Errorf("Wrong number of fields")
	}
	if len(rows) != 1 {
		t.Errorf("Wrong number of rows")
	}
	if len(rows[0]) != 2 {
		t.Errorf("Wrong number of columns")
	}
	if rows[0][1] != "7/8/2022 20:57:45" {
		t.Errorf("Wrong datestamp value")
	}
}

func TestMssqlParser_16x_typesResponse(t *testing.T) {
	mssql := mssqlModForTests(nil)

	data := []byte("040101b6003501008108000000000009" +
		"00260402690064000000000009006300" +
		"1000000904d000340108006500780061" +
		"006d0070006c00650034000476006100" +
		"6c003100000000000900ef02000904d0" +
		"003404760061006c0032000000000009" +
		"00af01000904d0003404760061006c00" +
		"330000000000090023001000000904d0" +
		"00340108006500780061006d0070006c" +
		"006500340004760061006c0034000000" +
		"00000900a701000904d0003404760061" +
		"006c0035000000000009006c11120004" +
		"760061006c0036000000000009006d08" +
		"04760061006c003700d1040a00000010" +
		"64756d6d792074657874707472000000" +
		"64756d6d795453000c00000074006500" +
		"78007400200031000200610001006210" +
		"64756d6d792074657874707472000000" +
		"64756d6d795453000600000074657874" +
		"203401006305012b000000081f85eb51" +
		"b81e0940d1040f0000001064756d6d79" +
		"207465787470747200000064756d6d79" +
		"54530008000000650078002000310002" +
		"0078000100791064756d6d7920746578" +
		"7470747200000064756d6d7954530004" +
		"0000006578203401007a0501f4010000" +
		"08000000000000d03ffd1000c1000200" +
		"000000000000")

	message, err := hex.DecodeString(string(data))
	if err != nil {
		t.Error("Failed to decode hex string")
	}

	stream := &mssqlStream{data: message, message: new(mssqlMessage)}

	ok, complete := mssql.mssqlMessageParser(stream)

	if !ok {
		t.Error("Parsing returned error")
	}
	if !complete {
		t.Error("Expecting a complete message")
	}
	if stream.message.isRequest {
		t.Error("Failed to parse MSSQL response")
	}
	if stream.message.size != 438 {
		t.Errorf("Wrong message size %d", stream.message.size)
	}

	// parse fields and rows
	raw := stream.data[stream.message.start:stream.message.end]
	if len(raw) == 0 {
		t.Errorf("Empty raw data")
	}
	fields, rows := parseQueryResponse(raw)
	if len(fields) != 8 {
		t.Errorf("Wrong number of fields")
	}
	if len(rows) != 2 {
		t.Errorf("Wrong number of rows")
	}
	if len(rows[0]) != 8 {
		t.Errorf("Wrong number of columns")
	}
	if rows[0][7] != "3.140000" {
		t.Errorf("Wrong datestamp value")
	}
}
