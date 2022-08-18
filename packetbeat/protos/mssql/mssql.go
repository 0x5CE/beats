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
	"fmt"
	"math"
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
	isError       bool
	errorCode     uint32
	errorInfo     string
	query         string
	ignoreMessage bool
	login         bool
	rowCount      uint64

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
	bytesOut uint64
	bytesIn  uint64
	notes    []string
	isError  bool

	mssql mapstr.M

	requestRaw  string
	responseRaw string
}

type mssqlStream struct {
	data []byte

	parseOffset int
	parseState  parseState
	isClient    bool

	message *mssqlMessage
}

// column types
const (
	dataType_NCHAR     = 0xEF
	dataType_BIGVARCHR = 0xA7
	dataType_BIGCHAR   = 0xAF
	dataType_TEXT      = 0x23
	dataType_NTEXT     = 0x63
	dataType_MONEYN    = 0x6E
	dataType_FLTN      = 0x6D
	dataType_NVARCHAR  = 0xE7
	dataType_INTN      = 0x26
	dataType_MONEY     = 0x3C
	dataType_FLT8      = 0x3E
	dataType_FLT4      = 0x3B
	dataType_DATETIME  = 0x3D
	dataType_NUMERICN  = 0x6C
	dataType_INT1      = 0x30
)

// token types
const (
	tokenType_METADATA  = 0x81
	tokenType_NVCHG     = 0xE3
	tokenType_INFO      = 0xAB
	tokenType_LOGIN_ACK = 0xAD
	tokenType_ROW       = 0xD1
	tokenType_NBCROW    = 0xD2
)

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

	// state
	version      byte
	versionMinor byte
	dbName       string

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
		return mssql.parseResponse(s)
	case 0x12:
		return parsePrelogin(s)
	default:
		logp.Debug("mssqldetailed", "MSSQL unknown message type = %d", msgType)
		s.message.size = 1
		return false, false
	}
}

func (mssql *mssqlPlugin) parseResponse(s *mssqlStream) (bool, bool) {
	s.message.isRequest = false
	s.message.start = s.parseOffset

	length := binary.BigEndian.Uint16(s.data[s.parseOffset+2:])

	logp.Debug("mssqldetailed", "Parsing response")

	if int(length) > len(s.data) {
		logp.Debug("mssqldetailed", "parseresponse: Incomplete message")
		return true, false
	}

	s.parseOffset = int(length)
	s.message.end = s.parseOffset
	s.message.size = uint64(s.message.end - s.message.start)

	offset := 8
	var expectDoneToken bool
	if s.data[offset] == tokenType_METADATA { // metadata
		expectDoneToken = true
	}
	for {
		tokenType := s.data[offset]

		switch tokenType {
		case 00: // prelogin
			s.message.ignoreMessage = true
			offset = int(length) // break

		case tokenType_NVCHG: // envchange
			tokenSize := binary.LittleEndian.Uint16(s.data[offset+1:])
			changeType := s.data[offset+3]
			if changeType == 0x01 { // database changed
				nameLen := s.data[offset+4]
				mssql.dbName = utf16ToUtf8(s.data[offset+5 : offset+5+int(nameLen*2)])
			}
			offset += int(tokenSize) + 3
			logp.Debug("mssqldetailed", "envchange")

		case tokenType_INFO: // info
			tokenSize := binary.LittleEndian.Uint16(s.data[offset+1:])
			offset += int(tokenSize) + 3
			logp.Debug("mssqldetailed", "info token")

		case tokenType_LOGIN_ACK: // loginAck
			tokenSize := binary.LittleEndian.Uint16(s.data[offset+1:])
			offset += int(tokenSize) + 3
			s.message.login = true
			mssql.version = s.data[offset-4]
			mssql.versionMinor = s.data[offset-3]
			logp.Debug("mssqldetailed", "loginack")

		case 0xAA: // error
			tokenSize := binary.LittleEndian.Uint16(s.data[offset+1:])

			s.message.errorCode = binary.LittleEndian.Uint32(s.data[offset+3:])
			msgLen := binary.LittleEndian.Uint16(s.data[offset+9:])
			s.message.errorInfo = utf16ToUtf8(s.data[offset+11 : offset+11+int(msgLen*2)])

			offset += int(tokenSize) + 3
			logp.Debug("mssqldetailed", "error %X", s.message.errorCode)

		default:
			offset = int(length) // break
		}

		if offset >= int(length) {
			break
		}
	}

	// done / doneproc token
	offset = int(length) - 13
	if s.data[offset] == 0xFD || s.data[offset] == 0xFE {
		flags := uint64(binary.LittleEndian.Uint16(s.data[offset+1:]))
		if s.message.errorCode == 0 {
			if flags&0x0002 == 1 {
				s.message.notes = append(s.message.notes, "Error in done message")
				logp.Debug("mssqldetailed", "done token error")

			} else if flags&0x0100 == 1 {
				s.message.notes = append(s.message.notes, "Server error")
				logp.Debug("mssqldetailed", "done token server error")
			}
		}
		s.message.rowCount = binary.LittleEndian.Uint64(s.data[offset+5:])
		logp.Debug("mssqldetailed", "Row count %d", s.message.rowCount)
	} else if expectDoneToken {
		return true, false
	}

	return true, true
}

func parseQueryBatch(s *mssqlStream) (bool, bool) {
	s.message.isRequest = true
	s.message.start = s.parseOffset

	length := binary.BigEndian.Uint16(s.data[s.parseOffset+2:])

	logp.Debug("mssqldetailed", "parsequerybatch")

	if int(length) > len(s.data) {
		logp.Debug("mssqldetailed", "parsequerybatch: Incomplete message")
		return true, false
	}

	headerLen := binary.LittleEndian.Uint32(s.data[s.parseOffset+8:])
	headerType := binary.LittleEndian.Uint16(s.data[s.parseOffset+16:])

	if headerType != 0x02 {
		logp.Debug("mssqldetailed", "wrong header: %X", headerType)
		return false, true // wrong header
	}

	s.parseOffset += 8 + int(headerLen)

	// MSSQL uses UTF16
	strRaw := s.data[uint32(s.parseOffset):length]
	query := utf16ToUtf8(strRaw)

	s.message.query = strings.Trim(string(query), " \r\n\t")

	logp.Debug("mssqldetailed", "parse query: %s", s.message.query)

	s.parseOffset += len(strRaw)
	s.message.end += s.parseOffset
	s.message.size = uint64(s.message.end - s.message.start)

	return true, true
}

func parsePrelogin(s *mssqlStream) (bool, bool) {
	logp.Debug("mssqldetailed", "parse prelogin")

	msgSize := binary.BigEndian.Uint16(s.data[2:])
	if int(msgSize) > len(s.data) {
		logp.Debug("mssqldetailed", "parseprelogin: Incomplete message")
		return true, false
	}

	if s.data[8] == 0x16 { // ignore tls exchange
		s.message.ignoreMessage = true
	}

	s.message.isRequest = s.isClient
	s.message.size = 1
	return true, true
}

func parseQueryResponse(data []byte) ([]string, [][]string) {
	var respFields []string
	var respRows [][]string

	offset := 8 // skipping header
	length := len(data)

	var nCols int

	type Field struct {
		name    string
		lenSize int
		varLen  bool
		colType byte
	}
	var fields []Field

	for {
		tokenType := data[offset]
		offset += 1

		switch tokenType {
		// colmetadata
		case tokenType_METADATA:
			nMetaCols := binary.LittleEndian.Uint16(data[offset:])

			nCols = int(nMetaCols)

			offset += 2
			for i := uint16(0); i < nMetaCols; i++ {
				// todo: handle 16-bit userType
				offset += 6
				colType := data[offset]

				var colLen, lenSize int
				var varLen bool

				switch colType {
				// texttype / text
				// ntexttype
				case dataType_NTEXT, dataType_TEXT:
					varLen = true
					_ = int(binary.LittleEndian.Uint32(data[offset+1:]))
					offset += 10 // skip colation
					tableLen := binary.LittleEndian.Uint16(data[offset+1:])
					offset += 3 + (int(tableLen) * 2) // skip table name
					lenSize = 4

				// nchartype / nchar
				// bigvarchartype / varchar
				// bigchartype / char
				case dataType_NCHAR, dataType_BIGVARCHR, dataType_BIGCHAR:
					varLen = true
					offset += 8
					lenSize = 2

				// fltntype / float
				// moneyntype
				case dataType_MONEYN, dataType_FLTN:
					varLen = true
					lenSize = 1
					offset += 2

				case dataType_NVARCHAR: // nvarchartype
					_ = int(binary.LittleEndian.Uint16(data[offset+1:]))
					lenSize = 2
					varLen = true
					offset += 8 // skip collation

				case dataType_INTN: //intntype
					colLen = int(data[offset+1])
					if colLen <= 16 {
						lenSize = 1
					} else {
						lenSize = 1
					}
					varLen = true
					offset += 2

				// flt8type
				// moneytype
				case dataType_MONEY, dataType_FLT8:
					varLen = false
					lenSize = 8
					offset += 1

				case dataType_FLT4: // flt4type
					varLen = false
					lenSize = 4
					offset += 1

				case dataType_INT1: // int1type
					varLen = false
					lenSize = 1
					offset += 1

				case dataType_DATETIME: // datetimetype
					varLen = false
					lenSize = 8
					offset += 1

				case dataType_NUMERICN: // numerictype / numeric
					varLen = true
					offset += 4
					lenSize = 1

				default:
					varLen = false
					lenSize = 4
					offset += 1
				}

				colNameLen := data[offset]
				strRaw := data[offset+1 : offset+1+int(colNameLen*2)]
				colName := utf16ToUtf8(strRaw)

				logp.Debug("mssqldetailed", "parse col %s %d", colName, colType)

				fields = append(fields, Field{name: colName, lenSize: lenSize, varLen: varLen, colType: colType})
				respFields = append(respFields, colName)
				offset += len(strRaw) + 1
			}

		// row, NBCRow (with some null values)
		case tokenType_ROW, tokenType_NBCROW:
			var nNullBitmap = int((len(fields)-1)/8) + 1
			nullBitmap := make([]byte, nNullBitmap)

			if tokenType == tokenType_NBCROW {
				nullBitmap = data[offset : offset+nNullBitmap]
				offset += nNullBitmap
			} else {
				for i := 0; i < len(nullBitmap); i++ {
					nullBitmap[i] = 0x00
				}
			}

			var row []string
			for i := 0; i < nCols; i++ {
				var fieldSize uint32
				var field string

				if getNullmapBit(nullBitmap, i) {
					field = "NULL"
					logp.Debug("mssqldetailed", "parse null")
					row = append(row, field)
					continue
				}

				// ntexttype / texttype / text
				if fields[i].colType == dataType_NTEXT || fields[i].colType == dataType_TEXT {
					tpLen := data[offset]
					// skipping timestamp and textptr
					offset += int(tpLen) + 9
				}

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

				switch fields[i].colType {
				case dataType_INTN: // intntype
					field = intNtoString(data[offset:], fieldSize)

				case dataType_NUMERICN: // numerictype / numeric
					fs := fieldSize - 1
					sign := data[offset]
					field = intNtoString(data[offset+1:], fs)
					if sign == 0x01 {
						field = "-" + field
					}

				case dataType_INT1: // int1type
					field = strconv.Itoa(int(data[offset]))

				// texttype / text
				// bigvarchartype / varchar
				// bigchartype / char
				case dataType_BIGCHAR, dataType_BIGVARCHR, dataType_TEXT:
					field = string(data[offset : offset+int(fieldSize)])

				// ntexttype
				// nvarchartype
				// nchartype
				case dataType_NTEXT, dataType_NCHAR, dataType_NVARCHAR:
					field = utf16ToUtf8(data[offset : offset+int(fieldSize)])

				case dataType_DATETIME: // datetimetype
					days := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
					seconds := int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
					field = datatimetypeToString(days, seconds)

				case dataType_MONEYN: // moneyntype
					switch fieldSize {
					case 4:
						field = moneytype4ToString(data)
					case 8:
						field = moneytype8ToString(data)
					}

				case dataType_MONEY: // moneytype
					field = moneytype8ToString(data)

				case dataType_FLT4: // flt4type
					num := math.Float32frombits(binary.LittleEndian.Uint32(data[offset:]))
					field = fmt.Sprintf("%f", num)

				case dataType_FLT8: // flt8type
					num := math.Float64frombits(binary.LittleEndian.Uint64(data[offset:]))
					field = fmt.Sprintf("%f", num)

				case dataType_FLTN: // fltntype / float
					switch fieldSize {
					case 4:
						num := math.Float32frombits(binary.LittleEndian.Uint32(data[offset:]))
						field = fmt.Sprintf("%f", num)
					case 8:
						num := math.Float64frombits(binary.LittleEndian.Uint64(data[offset:]))
						field = fmt.Sprintf("%f", num)
					}
				}
				offset += int(fieldSize)
				row = append(row, field)
				logp.Debug("mssqldetailed", "parse row %s", field)
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

func utf16ToUtf8(raw []byte) string {
	decoder := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()
	str, _ := decoder.Bytes(raw)
	return string(str)
}

func datatimetypeToString(days, seconds int32) string {
	time := time.Unix(-2208988800+int64((int(days)*24*60*60)),
		1000000000*int64(-5*60*60+(seconds/300)))

	dateStr := strconv.Itoa(time.Day()) + "/" + strconv.Itoa(int(time.Month())) +
		"/" + strconv.Itoa(time.Year())
	timeStr := strconv.Itoa(time.Hour()) + ":" + strconv.Itoa(time.Minute()) +
		":" + strconv.Itoa(time.Second())

	return dateStr + " " + timeStr
}

func getNullmapBit(nullMap []byte, n int) bool {
	index := n / 8
	shift := n % 8
	return (0x01 & (nullMap[index] >> shift)) == 0x01
}

func intNtoString(data []byte, fieldSize uint32) string {
	offset := 0
	var field string
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
	return field
}

func moneytype8ToString(data []byte) string {
	mostSig := int32(binary.LittleEndian.Uint32(data[0:4]))
	leastSig := int32(binary.LittleEndian.Uint32(data[4:8]))

	total := (int64(math.Pow(2, 32))*int64(mostSig) + int64(leastSig))

	amount := total / 10000
	dec := total % 10000

	return fmt.Sprintf("%d.%02d", amount, dec)
}

func moneytype4ToString(data []byte) string {
	total := int64(int32(binary.LittleEndian.Uint32(data[4:8])))

	amount := total / 10000
	dec := total % 10000

	return fmt.Sprintf("%d.%02d", amount, dec)
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
	trans.requestRaw = query
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
	trans.endTime = msg.ts

	if msg.login {
		trans.query = "N/A"
		trans.mssql.Update(mapstr.M{
			"version":       int(mssql.version),
			"minor_version": int(mssql.versionMinor),
		})
		trans.notes = append(trans.notes, "Login successful")
	}

	if len(mssql.dbName) > 0 {
		trans.mssql.Update(mapstr.M{
			"db_name": mssql.dbName,
		})
	}

	if msg.rowCount > 0 {
		trans.mssql.Update(mapstr.M{
			"num_rows": msg.rowCount,
		})
	}

	// dumping in CSV & transaction
	if len(msg.raw) > 0 {
		fields, rows := parseQueryResponse(msg.raw)
		trans.responseRaw = common.DumpInCSVFormat(fields, rows)
		if len(fields) > 0 {
			trans.mssql.Update(mapstr.M{
				"num_fields": len(fields),
			})
		}
	}

	trans.notes = append(trans.notes, msg.notes...)

	mssql.publishTransaction(trans)
	logp.Debug("mssql", "Mssql transaction completed: %s %s", trans.query, trans.mssql)

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
