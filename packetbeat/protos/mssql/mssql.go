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

package mssql

import (
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"golang.org/x/text/encoding/unicode"

	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
)

var (
	unmatchedRequests  = monitoring.NewInt(nil, "mssql.unmatched_requests")
	unmatchedResponses = monitoring.NewInt(nil, "mssql.unmatched_responses")
)

type mssqlMessage struct {
	start int
	end   int

	ts            time.Time
	isRequest     bool
	size          uint64
	tables        string
	isError       bool
	errorCode     uint16
	errorInfo     string
	query         string
	ignoreMessage bool

	direction    uint8
	tcpTuple     common.TCPTuple
	cmdlineTuple *common.ProcessTuple
	raw          []byte
	notes        []string

	statementID    int
	numberOfParams int
}

type mssqlTransaction struct {
	tuple    common.TCPTuple
	src      common.Endpoint
	dst      common.Endpoint
	ts       time.Time
	endTime  time.Time
	query    string
	method   string
	path     string // for mssql, Path refers to the mssql table queried
	bytesOut uint64
	bytesIn  uint64
	notes    []string
	isError  bool

	mssql mapstr.M

	requestRaw  string
	responseRaw string

	params []string // for execute statement param
}

type mssqlStream struct {
	data []byte

	parseOffset int
	parseState  parseState
	isClient    bool

	message *mssqlMessage
}

type parseState int

const (
	mssqlStateStart parseState = iota
	mssqlStateEatMessage
	mssqlStateEatFields
	mssqlStateEatRows
)

var stateStrings = []string{
	"Start",
	"EatMessage",
	"EatFields",
	"EatRows",
}

func (state parseState) String() string {
	return stateStrings[state]
}

type mssqlPlugin struct {

	// config
	ports        []int
	maxStoreRows int
	maxRowLength int
	sendRequest  bool
	sendResponse bool

	transactions       *common.Cache
	transactionTimeout time.Duration

	// prepare statements cache
	prepareStatements       *common.Cache
	prepareStatementTimeout time.Duration

	results protos.Reporter
	watcher procs.ProcessesWatcher

	// function pointer for mocking
	handleMssql func(mssql *mssqlPlugin, m *mssqlMessage, tcp *common.TCPTuple,
		dir uint8, raw_msg []byte)
}

func init() {
	protos.Register("mssql", New)
}

func New(
	testMode bool,
	results protos.Reporter,
	watcher procs.ProcessesWatcher,
	cfg *conf.C,
) (protos.Plugin, error) {
	p := &mssqlPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, watcher, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (mssql *mssqlPlugin) init(results protos.Reporter, watcher procs.ProcessesWatcher, config *mssqlConfig) error {
	mssql.setFromConfig(config)

	mssql.transactions = common.NewCache(
		mssql.transactionTimeout,
		protos.DefaultTransactionHashSize)
	mssql.transactions.StartJanitor(mssql.transactionTimeout)

	// prepare statements cache
	mssql.prepareStatements = common.NewCache(
		mssql.prepareStatementTimeout,
		protos.DefaultTransactionHashSize)
	mssql.prepareStatements.StartJanitor(mssql.prepareStatementTimeout)

	mssql.handleMssql = handleMssql
	mssql.results = results
	mssql.watcher = watcher

	return nil
}

func (mssql *mssqlPlugin) setFromConfig(config *mssqlConfig) {
	mssql.ports = config.Ports
	mssql.maxRowLength = config.MaxRowLength
	mssql.maxStoreRows = config.MaxRows
	mssql.sendRequest = config.SendRequest
	mssql.sendResponse = config.SendResponse
	mssql.transactionTimeout = config.TransactionTimeout
	mssql.prepareStatementTimeout = config.StatementTimeout
}

func (mssql *mssqlPlugin) getTransaction(k common.HashableTCPTuple) *mssqlTransaction {
	v := mssql.transactions.Get(k)
	if v != nil {
		return v.(*mssqlTransaction)
	}
	return nil
}

// cache the prepare statement info
type mssqlStmtData struct {
	query           string
	numOfParameters int
}
type mssqlStmtMap map[int]*mssqlStmtData

func (mssql *mssqlPlugin) getStmtsMap(k common.HashableTCPTuple) mssqlStmtMap {
	v := mssql.prepareStatements.Get(k)
	if v != nil {
		return v.(mssqlStmtMap)
	}
	return nil
}

func (mssql *mssqlPlugin) GetPorts() []int {
	return mssql.ports
}

func (stream *mssqlStream) prepareForNewMessage() {
	stream.data = nil
	stream.parseState = mssqlStateStart
	stream.parseOffset = 0
	stream.message = nil
}

func (mssql *mssqlPlugin) isServerPort(port uint16) bool {
	for _, sPort := range mssql.ports {
		if uint16(sPort) == port {
			return true
		}
	}
	return false
}

type mssqlPrivateData struct {
	data [2]*mssqlStream
}

// Called when the parser has identified a full message.
func (mssql *mssqlPlugin) messageComplete(tcptuple *common.TCPTuple, dir uint8, stream *mssqlStream) {
	// all ok, ship it
	msg := stream.data[stream.message.start:stream.message.end]

	if !stream.message.ignoreMessage {
		mssql.handleMssql(mssql, stream.message, tcptuple, dir, msg)
	}

	// and reset message
	stream.prepareForNewMessage()
}

func (mssql *mssqlPlugin) ConnectionTimeout() time.Duration {
	return mssql.transactionTimeout
}

func (mssql *mssqlPlugin) Parse(pkt *protos.Packet, tcptuple *common.TCPTuple,
	dir uint8, private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseMssql exception")

	priv := mssqlPrivateData{}

	if private != nil {
		var ok bool
		priv, ok = private.(mssqlPrivateData)
		if !ok {
			priv = mssqlPrivateData{}
		}
	}

	if priv.data[dir] == nil {
		dstPort := tcptuple.DstPort
		if dir == tcp.TCPDirectionReverse {
			dstPort = tcptuple.SrcPort
		}
		priv.data[dir] = &mssqlStream{
			data:     pkt.Payload,
			message:  &mssqlMessage{ts: pkt.Ts},
			isClient: mssql.isServerPort(dstPort),
		}
	} else {
		// concatenate bytes
		priv.data[dir].data = append(priv.data[dir].data, pkt.Payload...)
		if len(priv.data[dir].data) > tcp.TCPMaxDataInStream {
			logp.Debug("mssql", "Stream data too large, dropping TCP stream")
			priv.data[dir] = nil
			return priv
		}
	}

	stream := priv.data[dir]
	for len(stream.data) > 0 {
		if stream.message == nil {
			stream.message = &mssqlMessage{ts: pkt.Ts}
		}

		ok, complete := mssql.mssqlMessageParser(priv.data[dir])

		logp.Debug("mssqldetailed", "mssqlMessageParser returned ok=%v complete=%v", ok, complete)
		if !ok {
			priv.data[dir] = nil
			logp.Debug("mssql", "Ignore MSSQL message. Drop tcp stream. Try parsing with the next segment")
			return priv
		}

		if complete {
			mssql.messageComplete(tcptuple, dir, stream)
		} else {
			// wait for more data
			break
		}
	}
	return priv
}

func (mssql *mssqlPlugin) mssqlMessageParser(s *mssqlStream) (bool, bool) {
	logp.Debug("mssqldetailed", "MSSQL parser called. parseState = %s", s.parseState)

	s.message.start = s.parseOffset
	s.message.end = s.parseOffset

	msgType := s.data[s.parseOffset]

	switch msgType {
	case 0x01:
		return parseQueryBatch(s)
	case 0x04:
		return parseResponse(s)
	case 0x12:
		return parsePrelogin(s)
	default:
		logp.Debug("mssqldetailed", "MSSQL unknown message type = %d", msgType)
		s.message.ignoreMessage = true
		s.message.size = 1
		return false, false
	}
}

func parseResponse(s *mssqlStream) (bool, bool) {
	s.message.isRequest = false
	s.message.size = 1

	length := binary.BigEndian.Uint16(s.data[s.parseOffset+2:])

	if int(length) < len(s.data) {
		return true, false
	}

	s.parseOffset += 8

	return true, true
}

func parseQueryBatch(s *mssqlStream) (bool, bool) {
	s.message.isRequest = true

	length := binary.BigEndian.Uint16(s.data[s.parseOffset+2:])

	if int(length) < len(s.data) {
		return true, false
	}

	headerLen := binary.LittleEndian.Uint32(s.data[s.parseOffset+8:])
	headerType := binary.LittleEndian.Uint16(s.data[s.parseOffset+16:])

	if headerType != 0x02 {
		return false, true // wrong header
	}

	// MSSQL uses UTF16
	decoder := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()
	query, _ := decoder.Bytes(s.data[uint32(s.parseOffset)+8+headerLen : length])

	s.message.query = strings.Trim(string(query), " \r\n\t")

	s.message.start = s.parseOffset
	s.message.end += len(s.message.query)
	s.message.end += 1 // type
	s.message.size = uint64(s.message.end - s.message.start)

	return true, true
}

func parsePrelogin(s *mssqlStream) (bool, bool) {
	s.message.isRequest = s.isClient
	s.message.size = 1
	s.message.ignoreMessage = true
	return true, true
}

func parseQueryResponse(data []byte) ([]string, [][]string) {
	var respFields []string
	var respRows [][]string

	offset := 0
	length := len(data)

	var nCols int

	type Field struct {
		name    string
		lenSize int
		varLen  bool
		varType int // 1: int	2: string
	}
	var fields []Field

	for {
		tokenType := data[offset]
		offset += 1

		switch tokenType {
		// colmetadata
		case 0x81:
			nMetaCols := binary.LittleEndian.Uint16(data[offset:])

			nCols = int(nMetaCols)

			offset += 2
			for i := uint16(0); i < nMetaCols; i++ {
				// todo: handle 16-bit userType
				offset += 6
				colType := data[offset]

				var colLen, lenSize, varType int
				var varLen bool
				switch colType {
				case 0xE7: // nvarchar
					_ = int(binary.LittleEndian.Uint16(data[offset+1:]))
					lenSize = 2
					varType = 2
					varLen = true
					offset += 8 // skip collation

				case 0x26: //intntype
					colLen = int(data[offset+1])
					if colLen <= 16 {
						lenSize = 1
					} else {
						lenSize = 1
					}
					varType = 1
					varLen = true
					offset += 2

				default:
					varType = 1
					varLen = false
					lenSize = 4
					offset += 1
				}

				colNameLen := data[offset]
				colName := string(data[offset+1 : offset+1+int(colNameLen*2)])
				fields = append(fields, Field{name: colName, lenSize: lenSize, varLen: varLen, varType: varType})
				respFields = append(respFields, colName)
				offset += len(colName) + 1
			}

		// row
		case 0xD1:
			var row []string
			for i := 0; i < nCols; i++ {
				var fieldSize uint32

				if fields[i].varLen {
					switch fields[i].lenSize {
					case 4:
						fieldSize = binary.LittleEndian.Uint32(data[offset:])
					case 2:
						fieldSize = uint32(binary.LittleEndian.Uint16(data[offset:]))
					case 1:
						fieldSize = uint32(data[offset])
					}
					offset += fields[i].lenSize
				} else {
					// fixed length
					fieldSize = uint32(fields[i].lenSize)
				}

				var field string

				switch fields[i].varType {
				case 1: // int
					switch fieldSize {
					case 1:
						field = strconv.Itoa(int(data[offset]))
					case 2:
						field = strconv.Itoa(int(binary.LittleEndian.Uint16(data[offset : offset+2])))
					case 4:
						field = strconv.Itoa(int(binary.LittleEndian.Uint32(data[offset : offset+4])))
					case 8:
						field = strconv.Itoa(int(binary.LittleEndian.Uint64(data[offset : offset+8])))
					}
				case 2: // string
					field = string(data[offset : offset+int(fieldSize)])
				}
				offset += int(fieldSize)
				row = append(row, field)
			}
			respRows = append(respRows, row)

		default:
			offset = int(length) // break
		}

		if offset >= int(length) {
			break
		}
	}

	return respFields, respRows
}

func getConnection(private protos.ProtocolData) *mssqlPrivateData {
	if private == nil {
		return nil
	}

	priv, ok := private.(*mssqlPrivateData)
	if !ok {
		logp.Warn("mssql connection type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: mssql connection data not set")
		return nil
	}
	return priv
}

func (mssql *mssqlPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool,
) {
	defer logp.Recover("GapInStream(mssql) exception")

	_ = getConnection(private)

	return nil, true
}

func (mssql *mssqlPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	return private
}

func handleMssql(mssql *mssqlPlugin, m *mssqlMessage, tcptuple *common.TCPTuple,
	dir uint8, rawMsg []byte,
) {
	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = mssql.watcher.FindProcessesTupleTCP(tcptuple.IPPort())
	m.raw = rawMsg

	if m.isRequest {
		mssql.receivedMssqlRequest(m)
	} else {
		mssql.receivedMssqlResponse(m)
	}
}

func (mssql *mssqlPlugin) receivedMssqlRequest(msg *mssqlMessage) {
	tuple := msg.tcpTuple
	trans := mssql.getTransaction(tuple.Hashable())

	if trans != nil {
		if trans.mssql != nil {
			logp.Debug("mssql", "Two requests without a Response. Dropping old request: %s", trans.mssql)
			unmatchedRequests.Add(1)
		}
	} else {
		trans = &mssqlTransaction{tuple: tuple}
		mssql.transactions.Put(tuple.Hashable(), trans)
	}

	trans.ts = msg.ts
	trans.src, trans.dst = common.MakeEndpointPair(msg.tcpTuple.BaseTuple, msg.cmdlineTuple)
	if msg.direction == tcp.TCPDirectionReverse {
		trans.src, trans.dst = trans.dst, trans.src
	}

	trans.query = msg.query

	query := strings.Trim(trans.query, " \r\n\t")
	index := strings.IndexAny(query, " \r\n\t")
	var method string
	if index > 0 {
		method = strings.ToUpper(query[:index])
	} else {
		method = strings.ToUpper(query)
	}

	trans.query = query
	trans.method = method

	trans.mssql = mapstr.M{}

	trans.notes = msg.notes

	// save Raw message
	trans.requestRaw = msg.query
	trans.bytesIn = msg.size
}

func (mssql *mssqlPlugin) receivedMssqlResponse(msg *mssqlMessage) {
	trans := mssql.getTransaction(msg.tcpTuple.Hashable())

	if trans == nil {
		logp.Debug("mssql", "Response from unknown transaction. Ignoring.")
		unmatchedResponses.Add(1)
		return
	}
	// check if the request was received
	if trans.mssql == nil {
		logp.Debug("mssql", "Response from unknown transaction. Ignoring.")
		unmatchedResponses.Add(1)
		return
	}

	trans.isError = msg.isError
	if trans.isError {
		trans.mssql["error_code"] = msg.errorCode
		trans.mssql["error_message"] = msg.errorInfo
	}
	if msg.statementID != 0 {
		// cache prepare statement response info
		stmts := mssql.getStmtsMap(msg.tcpTuple.Hashable())
		if stmts == nil {
			stmts = mssqlStmtMap{}
		}
		if stmts[msg.statementID] == nil {
			stmtData := &mssqlStmtData{
				query:           trans.query,
				numOfParameters: msg.numberOfParams,
			}
			stmts[msg.statementID] = stmtData
		}
		mssql.prepareStatements.Put(msg.tcpTuple.Hashable(), stmts)
		trans.notes = append(trans.notes, trans.query)
		trans.query = "Request Prepare Statement"
	}

	trans.bytesOut = msg.size
	trans.path = msg.tables
	trans.endTime = msg.ts

	trans.notes = append(trans.notes, msg.notes...)

	mssql.publishTransaction(trans)
	logp.Debug("mssql", "Mssql transaction completed: %s %s %s", trans.query, trans.params, trans.mssql)

	mssql.transactions.Delete(trans.tuple.Hashable())
}

func (mssql *mssqlPlugin) publishTransaction(t *mssqlTransaction) {
	if mssql.results == nil {
		return
	}

	logp.Debug("mssql", "mssql.results exists")

	evt, pbf := pb.NewBeatEvent(t.ts)
	pbf.SetSource(&t.src)
	pbf.AddIP(t.src.IP)
	pbf.SetDestination(&t.dst)
	pbf.AddIP(t.dst.IP)
	pbf.Source.Bytes = int64(t.bytesIn)
	pbf.Destination.Bytes = int64(t.bytesOut)
	pbf.Event.Dataset = "mssql"
	pbf.Event.Start = t.ts
	pbf.Event.End = t.endTime
	pbf.Network.Transport = "tcp"
	pbf.Network.Protocol = "mssql"
	pbf.Error.Message = t.notes

	fields := evt.Fields
	fields["type"] = pbf.Event.Dataset
	fields["method"] = t.method
	fields["query"] = t.query
	fields["mssql"] = t.mssql
	if len(t.path) > 0 {
		fields["path"] = t.path
	}
	if len(t.params) > 0 {
		fields["params"] = t.params
	}

	if t.isError {
		fields["status"] = common.ERROR_STATUS
	} else {
		fields["status"] = common.OK_STATUS
	}

	if mssql.sendRequest {
		fields["request"] = t.requestRaw
	}
	if mssql.sendResponse {
		fields["response"] = t.responseRaw
	}

	mssql.results(evt)
}
