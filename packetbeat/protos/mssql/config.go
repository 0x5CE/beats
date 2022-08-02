package mssql

import (
	"github.com/elastic/beats/v7/packetbeat/config"
	"github.com/elastic/beats/v7/packetbeat/protos"
)

type mssqlConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = mssqlConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)

func (c *mssqlConfig) Validate() error {
	return nil
}
