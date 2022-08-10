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
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
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

func TestMssqlParser_16x_nullColsResponse(t *testing.T) {
	mssql := mssqlModForTests(nil)

	data := []byte("04010134003501008110000000000009" +
		"00a701000904d0003401610000000000" +
		"0900a701000904d00034016200000000" +
		"000900a701000904d000340163000000" +
		"00000900a701000904d0003401640000" +
		"0000000900a701000904d00034016500" +
		"000000000900a701000904d000340166" +
		"00000000000900a701000904d0003401" +
		"6700000000000900a701000904d00034" +
		"016800000000000900a701000904d000" +
		"34016900000000000900a701000904d0" +
		"0034016a00000000000900a701000904" +
		"d00034016b00000000000900a7010009" +
		"04d00034016c00000000000900a70100" +
		"0904d00034016d00000000000900a701" +
		"000904d00034016e00000000000900a7" +
		"01000904d00034016f00000000000900" +
		"a701000904d00034017000d23eff0100" +
		"41010047010048fd1000c10001000000" +
		"00000000")

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
	if stream.message.size != 308 {
		t.Errorf("Wrong message size %d", stream.message.size)
	}

	// parse fields and rows
	raw := stream.data[stream.message.start:stream.message.end]
	if len(raw) == 0 {
		t.Errorf("Empty raw data")
	}
	fields, rows := parseQueryResponse(raw)
	if len(fields) != 16 {
		t.Errorf("Wrong number of fields")
	}
	if len(rows) != 1 {
		t.Errorf("Wrong number of rows")
	}
	if len(rows[0]) != 16 {
		t.Errorf("Wrong number of columns")
	}
	if rows[0][3] != "NULL" {
		t.Errorf("Wrong column")
	}
}

func TestMssql_16x_Login(t *testing.T) {
	mssql := mssqlModForTests(nil)
	// prelogin
	data, err := hex.DecodeString("120100580000010000001f0006010025" +
		"00010200260001030027000404002b00" +
		"0105002c0024ff110a00010000000000" +
		"000000006a0a32e033511c10425ad9ce" +
		"a26b69c8096d9dac950af77ac1618566" +
		"f269c6e800000000")
	if err != nil {
		t.Errorf("Failed to decode string")
	}
	ts, err := time.Parse(time.RFC3339, "2000-12-26T01:15:06+04:20")
	if err != nil {
		t.Errorf("Failed to get ts")
	}
	pkt := protos.Packet{
		Payload: data,
		Ts:      ts,
	}
	var tuple common.TCPTuple
	var private mssqlPrivateData

	var loggedIn bool
	countHandleMssql := 0

	mssql.handleMssql = func(mssql *mssqlPlugin, m *mssqlMessage, tcp *common.TCPTuple,
		dir uint8, raw_msg []byte,
	) {
		if m.login {
			loggedIn = true
		}
		countHandleMssql++
	}
	mssql.Parse(&pkt, &tuple, tcp.TCPDirectionOriginal, private)

	// server response
	data, err = hex.DecodeString("040101b900350100e31b0001066d0061" +
		"007300740065007200066d0061007300" + "740065007200ab600045160000020025" +
		"004300680061006e0067006500640020" + "00640061007400610062006100730065" +
		"00200063006f006e0074006500780074" + "00200074006f00200027006d00610073" +
		"0074006500720027002e000473007100" + "6c0031000001000000e3080007050904" +
		"d0003400e31700020a750073005f0065" + "006e0067006c0069007300680000ab64" +
		"0047160000010027004300680061006e" + "0067006500640020006c0061006e0067" +
		"00750061006700650020007300650074" + "00740069006e006700200074006f0020" +
		"00750073005f0065006e0067006c0069" + "00730068002e0004730071006c003100" +
		"0001000000ad36000174000004164d00" + "6900630072006f0073006f0066007400" +
		"2000530051004c002000530065007200" + "7600650072000000000010000258e313" +
		"00040434003000390036000434003000" + "39003600ae0b01000000000902000000" +
		"01010a0100000001012e000000000900" + "608114ffe7ffff000202070104010005" +
		"04ffffffff0601000701020808000000" + "00000000000904fffffffffffd000000" +
		"000000000000000000")
	if err != nil {
		t.Errorf("Failed to decode string")
	}
	pkt = protos.Packet{
		Payload: data,
		Ts:      ts,
	}
	mssql.Parse(&pkt, &tuple, tcp.TCPDirectionOriginal, private)

	if !loggedIn {
		t.Errorf("mssql login failed")
	}

	if mssql.version != 16 {
		t.Errorf("mssql login wrong version")
	}

	if countHandleMssql != 2 {
		t.Errorf("handleMssql not called")
	}
}

func TestMssqlParser_15x_query(t *testing.T) {
	mssql := mssqlModForTests(nil)

	data := []byte(
		"0101004a000001001600000012000000" +
			"02000000000000000000010000005300" +
			"45004c0045004300540020002a002000" +
			"460052004f004d0020006d006f007600" +
			"69006500730031000a00")

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
	if stream.message.query != "SELECT * FROM movies1" {
		t.Error("Failed to parse query")
	}
	if stream.message.size != 74 {
		t.Errorf("Wrong message size %d", stream.message.size)
	}
}

func TestMssqlParser_15x_response(t *testing.T) {
	mssql := mssqlModForTests(nil)

	data := []byte("04010060003801008102000000000009" +
		"0026040269006400000000000900e7c8" +
		"000904d00034046e0061006d006500d1" +
		"040a0000001c00460061007300740020" +
		"002600200046007500720069006f0075" +
		"007300fd1000c1000100000000000000")

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
	if stream.message.size != 96 {
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
}

func TestMssql_15x_Login(t *testing.T) {
	mssql := mssqlModForTests(nil)
	// prelogin
	data, err := hex.DecodeString("120100580000010000001f0006010025" +
		"00010200260001030027000404002b00" +
		"0105002c0024ff110a00010000000000" +
		"00000000c9aab14d52d08f7404350e01" +
		"e4424428fb94f8da059204fd8a2ed2e8" +
		"f6f6bbef00000000")
	if err != nil {
		t.Errorf("Failed to decode string")
	}
	ts, err := time.Parse(time.RFC3339, "2000-12-26T01:15:06+04:20")
	if err != nil {
		t.Errorf("Failed to get ts")
	}
	pkt := protos.Packet{
		Payload: data,
		Ts:      ts,
	}
	var tuple common.TCPTuple
	var private mssqlPrivateData

	var loggedIn bool
	countHandleMssql := 0

	mssql.handleMssql = func(mssql *mssqlPlugin, m *mssqlMessage, tcp *common.TCPTuple,
		dir uint8, raw_msg []byte,
	) {
		if m.login {
			loggedIn = true
		}
		countHandleMssql++
	}
	mssql.Parse(&pkt, &tuple, tcp.TCPDirectionOriginal, private)

	// server response
	data, err = hex.DecodeString("040101fb00380100e31b0001066d0061" +
		"007300740065007200066d0061007300" + "740065007200ab840045160000020025" +
		"004300680061006e0067006500640020" + "00640061007400610062006100730065" +
		"00200063006f006e0074006500780074" + "00200074006f00200027006d00610073" +
		"0074006500720027002e00166d007500" + "61007a007a0061006d002d004c006100" +
		"7400690074007500640065002d004500" + "35003400370030000001000000e30800" +
		"07050904d0003400e31700020a750073" + "005f0065006e0067006c006900730068" +
		"0000ab88004716000001002700430068" + "0061006e0067006500640020006c0061" +
		"006e0067007500610067006500200073" + "0065007400740069006e006700200074" +
		"006f002000750073005f0065006e0067" + "006c006900730068002e00166d007500" +
		"61007a007a0061006d002d004c006100" + "7400690074007500640065002d004500" +
		"35003400370030000001000000ad3600" + "0174000004164d006900630072006f00" +
		"73006f00660074002000530051004c00" + "20005300650072007600650072000000" +
		"00000f00108ce3130004043400300039" + "003600043400300039003600ae090200" +
		"000001010a0100000001012e00000000" + "0900608114ffe7ffff00020207010401" +
		"000504ffffffff060100070102080800" + "000000000000000904fffffffffffd00" +
		"0000000000000000000000")
	if err != nil {
		t.Errorf("Failed to decode string")
	}
	pkt = protos.Packet{
		Payload: data,
		Ts:      ts,
	}
	mssql.Parse(&pkt, &tuple, tcp.TCPDirectionOriginal, private)

	if !loggedIn {
		t.Errorf("mssql login failed")
	}

	if mssql.version != 15 {
		t.Errorf("mssql login wrong version")
	}

	if countHandleMssql != 2 {
		t.Errorf("handleMssql not called")
	}
}
