package mirror

import (
	"fmt"
	"strings"

	"github.com/qpoint-io/qtap/pkg/plugins"
	"go.uber.org/zap"
)

func (i *mirrorInstance) OnRedisCommand(cmd *plugins.RedisCommand) plugins.RedisStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.RedisStatusContinue
	}

	payload := cmd.Raw
	if len(payload) == 0 {
		return plugins.RedisStatusContinue
	}

	src := i.connSrv.OpenEvent().Local
	dst := i.connSrv.OpenEvent().Remote

	if err := i.tcp.SendFromSrc(src, dst, payload); err != nil {
		i.logger.Error("error sending Redis command to TAP device", zap.Error(err))
	}

	return plugins.RedisStatusContinue
}

func (i *mirrorInstance) OnRedisResult(res *plugins.RedisResult) plugins.RedisStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.RedisStatusContinue
	}

	// For Redis results, we reconstruct a simple string representation if we don't have raw bytes
	// TODO: if we had raw bytes for results, we should use them
	payload := []byte(fmt.Sprintf("%v\r\n", res.Value))
	src := i.connSrv.OpenEvent().Remote
	dst := i.connSrv.OpenEvent().Local

	if err := i.tcp.SendFromDst(src, dst, payload); err != nil {
		i.logger.Error("error sending Redis result to TAP device", zap.Error(err))
	}

	return plugins.RedisStatusContinue
}

func (i *mirrorInstance) OnMySQLCommand(cmd *plugins.MySQLCommand) plugins.MySQLStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.MySQLStatusContinue
	}

	payload := []byte(cmd.Query)
	if len(payload) == 0 {
		return plugins.MySQLStatusContinue
	}

	src := i.connSrv.OpenEvent().Local
	dst := i.connSrv.OpenEvent().Remote

	if err := i.tcp.SendFromSrc(src, dst, payload); err != nil {
		i.logger.Error("error sending MySQL command to TAP device", zap.Error(err))
	}

	return plugins.MySQLStatusContinue
}

func (i *mirrorInstance) OnMySQLResult(res *plugins.MySQLResult) plugins.MySQLStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.MySQLStatusContinue
	}

	// Reconstruct a minimal summary for MySQL results
	var sb strings.Builder
	if res.Type == "Error" {
		fmt.Fprintf(&sb, "Error %d: %s\r\n", res.ErrorCode, res.ErrorMessage)
	} else {
		fmt.Fprintf(&sb, "%s: %d rows affected\r\n", res.Type, res.AffectedRows)
	}

	payload := []byte(sb.String())
	src := i.connSrv.OpenEvent().Remote
	dst := i.connSrv.OpenEvent().Local

	if err := i.tcp.SendFromDst(src, dst, payload); err != nil {
		i.logger.Error("error sending MySQL result to TAP device", zap.Error(err))
	}

	return plugins.MySQLStatusContinue
}

func (i *mirrorInstance) OnKafkaCommand(cmd *plugins.KafkaCommand) plugins.KafkaStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.KafkaStatusContinue
	}

	payload := []byte(plugins.BuildKafkaStatement(cmd))
	src := i.connSrv.OpenEvent().Local
	dst := i.connSrv.OpenEvent().Remote

	if err := i.tcp.SendFromSrc(src, dst, payload); err != nil {
		i.logger.Error("error sending Kafka command to TAP device", zap.Error(err))
	}

	return plugins.KafkaStatusContinue
}

func (i *mirrorInstance) OnKafkaResult(res *plugins.KafkaResult) plugins.KafkaStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.KafkaStatusContinue
	}

	// We don't have the original command here, so we just send the result summary if possible
	// However, BuildKafkaResponseSummary needs the command.
	// For now, we'll just send a simple message.
	summary := fmt.Sprintf("Kafka Response: ErrorCode=%d", res.ErrorCode)
	if res.IsError {
		summary += " " + res.ErrorMessage
	}

	payload := []byte(summary + "\r\n")
	src := i.connSrv.OpenEvent().Remote
	dst := i.connSrv.OpenEvent().Local

	if err := i.tcp.SendFromDst(src, dst, payload); err != nil {
		i.logger.Error("error sending Kafka result to TAP device", zap.Error(err))
	}

	return plugins.KafkaStatusContinue
}
