package mirror

import (
	"fmt"
	"hash/fnv"
	"os"
	"strings"

	"github.com/qpoint-io/qtap/pkg/plugins"
	"github.com/qpoint-io/qtap/pkg/services"
	"github.com/qpoint-io/qtap/pkg/services/connmeta"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const (
	PluginTypeMirror plugins.PluginType = "mirror"
)

type Config struct {
	InterfaceName string `yaml:"interface_name" json:"interface_name"`
}

type Factory struct {
	logger *zap.Logger
	config Config

	tapHandle *os.File
}

func (f *Factory) Init(logger *zap.Logger, config yaml.Node) {
	f.logger = logger

	if err := config.Decode(&f.config); err != nil {
		logger.Error("error decoding config", zap.Error(err))
	}

	if f.config.InterfaceName != "" {
		logger.Debug("initializing mirror plugin", zap.String("interface_name", f.config.InterfaceName))
		if tapHandle, err := OpenTap(f.config.InterfaceName); err != nil {
			logger.Error("failed to open TAP device", zap.Error(err))
		} else {
			f.tapHandle = tapHandle
		}
	}
}

func (f *Factory) NewHttpInstance(ctx plugins.PluginContext, svcs *services.ServiceRegistry) plugins.HttpPluginInstance {
	return f.newInstance(ctx, svcs)
}

func (f *Factory) NewGrpcInstance(ctx plugins.PluginContext, svcs *services.ServiceRegistry) plugins.GrpcPluginInstance {
	return f.newInstance(ctx, svcs)
}

func (f *Factory) NewRedisInstance(ctx plugins.PluginContext, svcs *services.ServiceRegistry) plugins.RedisPluginInstance {
	return f.newInstance(ctx, svcs)
}

func (f *Factory) NewMySQLInstance(ctx plugins.PluginContext, svcs *services.ServiceRegistry) plugins.MySQLPluginInstance {
	return f.newInstance(ctx, svcs)
}

func (f *Factory) NewKafkaInstance(ctx plugins.PluginContext, svcs *services.ServiceRegistry) plugins.KafkaPluginInstance {
	return f.newInstance(ctx, svcs)
}

func (f *Factory) newInstance(ctx plugins.PluginContext, svcs *services.ServiceRegistry) *mirrorInstance {
	f.logger.Debug("new mirror plugin instance created")

	var connSrv connmeta.Service
	svc, err := services.GetService[connmeta.Service](ctx.Context(), svcs, connmeta.Type, "")
	if err != nil {
		f.logger.Error("failed to get connmeta service for mirror plugin", zap.Error(err))
	} else {
		connSrv = svc
	}

	// Initialize sequence numbers with a deterministic starting point based on the connection ID
	h := fnv.New32a()
	h.Write([]byte(ctx.Meta().ConnectionID()))
	startSeq := h.Sum32()

	tcpMirror := NewTCPMirror(f.tapHandle, startSeq, startSeq+0x10000000)

	fi := &mirrorInstance{
		logger:    f.logger,
		ctx:       ctx,
		tapHandle: f.tapHandle,
		connSrv:   connSrv,
		tcp:       tcpMirror,
	}

	return fi
}

func (f *Factory) Destroy() {
	if f.tapHandle != nil {
		f.logger.Debug("closing TAP device", zap.String("interface_name", f.config.InterfaceName))
		f.tapHandle.Close()
	}
}

func (f *Factory) PluginType() plugins.PluginType {
	return PluginTypeMirror
}

type mirrorInstance struct {
	logger    *zap.Logger
	ctx       plugins.PluginContext
	tapHandle *os.File

	connSrv connmeta.Service

	tcp *TCPMirror
}

func (i *mirrorInstance) Destroy() {}

func (i *mirrorInstance) RequestHeaders(headers plugins.Headers, endOfStream bool) plugins.HeadersStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.HeadersStatusContinue
	}

	method, _ := headers.Get(":method")
	path, _ := headers.Get(":path")

	// Reconstruct the HTTP Request Line (e.g., "GET /index.html HTTP/1.1")
	// We hardcode HTTP/1.1 for better compatibility with IDS/IPS like Suricata
	var headerStr strings.Builder
	fmt.Fprintf(&headerStr, "%s %s HTTP/1.1\r\n", method, path)
	for name, value := range headers.All() {
		if name[0] != ':' { // Skip pseudo-headers
			fmt.Fprintf(&headerStr, "%s: %s\r\n", name, value)
		}
	}
	headerStr.WriteString("\r\n") // End of headers

	payload := []byte(headerStr.String())
	src := i.connSrv.OpenEvent().Local
	dst := i.connSrv.OpenEvent().Remote

	// Let TCPMirror handle chunking, sequencing and sending
	if err := i.tcp.SendFromSrc(src, dst, payload); err != nil {
		i.logger.Error("error sending HTTP headers to TAP device", zap.Error(err))
	}

	return plugins.HeadersStatusContinue
}

func (i *mirrorInstance) RequestBody(frame plugins.BodyBuffer, endOfStream bool) plugins.BodyStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.BodyStatusContinue
	}

	payload := frame.Copy()
	if len(payload) == 0 {
		return plugins.BodyStatusContinue
	}

	src := i.connSrv.OpenEvent().Local
	dst := i.connSrv.OpenEvent().Remote

	// Let TCPMirror handle chunking, sequencing and sending
	if err := i.tcp.SendFromSrc(src, dst, payload); err != nil {
		i.logger.Error("error sending HTTP body to TAP device", zap.Error(err))
	}

	return plugins.BodyStatusContinue
}

func (i *mirrorInstance) ResponseHeaders(headers plugins.Headers, endOfStream bool) plugins.HeadersStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.HeadersStatusContinue
	}

	status, _ := headers.Get(":status")

	// Reconstruct the HTTP Status Line (e.g., "HTTP/1.1 200 OK")
	// We hardcode HTTP/1.1 for better compatibility with IDS/IPS like Suricata
	var headerStr strings.Builder
	fmt.Fprintf(&headerStr, "HTTP/1.1 %s\r\n", status)
	for name, value := range headers.All() {
		if name[0] != ':' { // Skip pseudo-headers
			fmt.Fprintf(&headerStr, "%s: %s\r\n", name, value)
		}
	}
	headerStr.WriteString("\r\n") // End of headers

	payload := []byte(headerStr.String())
	src := i.connSrv.OpenEvent().Remote
	dst := i.connSrv.OpenEvent().Local

	if err := i.tcp.SendFromDst(src, dst, payload); err != nil {
		i.logger.Error("error sending HTTP response headers to TAP device", zap.Error(err))
	}

	return plugins.HeadersStatusContinue
}

func (i *mirrorInstance) ResponseBody(frame plugins.BodyBuffer, endOfStream bool) plugins.BodyStatus {
	if i.tapHandle == nil || i.connSrv == nil {
		return plugins.BodyStatusContinue
	}

	payload := frame.Copy()
	if len(payload) == 0 {
		return plugins.BodyStatusContinue
	}

	src := i.connSrv.OpenEvent().Remote
	dst := i.connSrv.OpenEvent().Local

	if err := i.tcp.SendFromDst(src, dst, payload); err != nil {
		i.logger.Error("error sending HTTP response body chunk to TAP device", zap.Error(err))
	}

	return plugins.BodyStatusContinue
}
