package tzservice

import (
	"slices"
	"strings"

	"flashcat.cloud/categraf/config"
)

type ServiceConfig struct {
	BaseDir          string                          `json:"basedir" yaml:"basedir" toml:"basedir"`
	CacheTTL         int                             `json:"cache_ttl" yaml:"cache_ttl" toml:"cache_ttl"`
	HttpProvider     *HttpServiceInfoProviderConfig  `json:"http_provider" yaml:"http_provider" toml:"http_provider"`
	FileProvider     *FileServiceInfoProviderConfig  `json:"file_provider" yaml:"file_provider" toml:"file_provider"`
	RedisProvider    *RedisServiceInfoProviderConfig `json:"redis_provider" yaml:"redis_provider" toml:"redis_provider"`
	CmdbProvider     *CmdbServiceInfoProviderConfig  `json:"cmdb_provider" yaml:"cmdb_provider" toml:"cmdb_provider"`
	ProcessFilter    string                          `json:"process_filter" yaml:"process_filter" toml:"process_filter"`
	DisableFileCount bool                            `json:"disable_filecount" yaml:"disable_filecount" toml:"disable_filecount"`
	WsURL            string                          `json:"ws_url" yaml:"ws_url" toml:"ws_url"`
}

type HttpServiceInfoProviderConfig struct {
	ApiUrl    string `json:"api_url" yaml:"api_url" toml:"api_url"`
	SecretKey string `json:"secret_key" yaml:"secret_key" toml:"secret_key"`
	Mode      int8   `json:"mode" yaml:"mode" toml:"mode"`
}
type FileServiceInfoProviderConfig struct {
	Path string `json:"path" yaml:"path" toml:"path"`
	Mode int8   `json:"mode" yaml:"mode" toml:"mode"`
}

type RedisServiceInfoProviderConfig struct {
	Addr     string `json:"addr" yaml:"addr" toml:"addr"`
	Password string `json:"password" yaml:"password" toml:"password"`
	DB       int    `json:"db" yaml:"db" toml:"db"`
	Mode     int8   `json:"mode" yaml:"mode" toml:"mode"`
}

type CmdbServiceInfoProviderConfig struct {
	BaseURL     string `json:"base_url" yaml:"base_url" toml:"base_url"`
	AccessKey   string `json:"access_key" yaml:"access_key" toml:"access_key"`
	SecretKey   string `json:"secret_key" yaml:"secret_key" toml:"secret_key"`
	Model       string `json:"model" yaml:"model" toml:"model"`
	ProjectCode string `json:"project_code" yaml:"project_code" toml:"project_code"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level     string `json:"level" yaml:"level" toml:"level"`
	Stdout    bool   `json:"stdout" yaml:"stdout" toml:"stdout"`
	Format    string `json:"format" yaml:"format" toml:"format"`
	Path      string `json:"path" yaml:"path" toml:"path"`
	LeaveDays int    `json:"leave_days" yaml:"leave_days" toml:"leave_days"`
}

type CollectCheckConfig struct {
	ServiceId    string   `json:"service_id" toml:"service_id" yaml:"service_id"`          // 服务ID（模糊匹配）
	ServiceName  string   `json:"service_name" toml:"service_name" yaml:"service_name"`    // 服务名称（模糊匹配）
	ServiceTypes []string `json:"service_types" toml:"service_types" yaml:"service_types"` // 服务类型（包含）
}

func (c *CollectCheckConfig) Match(info *serviceInfo) bool {
	if c.ServiceId != "" && !strings.Contains(info.ServiceId, c.ServiceId) {
		return false
	}
	if c.ServiceName != "" && !strings.Contains(info.Name, c.ServiceName) {
		return false
	}
	if len(c.ServiceTypes) > 0 && !slices.Contains(c.ServiceTypes, info.ServiceType) {
		return false
	}
	return true
}

func (c *CollectCheckConfig) Filter(infos []*serviceInfo) []*serviceInfo {
	filtered := make([]*serviceInfo, 0, len(infos))
	for _, info := range infos {
		if c.Match(info) {
			filtered = append(filtered, info)
		}
	}
	return filtered
}

// CollectConfig 采集配置
type CollectConfig struct {
	config.InstanceConfig
	Name     string              `json:"name" toml:"name" yaml:"name"`
	Iterate  bool                `json:"iterate" toml:"iterate" yaml:"iterate"`
	Parallel bool                `json:"parallel" toml:"parallel" yaml:"parallel"`
	Http     *HttpRequestConfig  `json:"http" toml:"http" yaml:"http"`
	Cmd      *CmdRequestConfig   `json:"cmd" toml:"cmd" yaml:"cmd"`
	Check    *CollectCheckConfig `json:"check" toml:"check" yaml:"check"`
	Parse    ParseConfig         `json:"parse" toml:"parse" yaml:"parse"`
	Mappings []MappingConfig     `json:"mapping" toml:"mapping" yaml:"mapping"`
}

type HttpRequestConfig struct {
	Method   string            `json:"method" toml:"method" yaml:"method"`
	URL      string            `json:"url" toml:"url" yaml:"url"`
	Header   map[string]string `json:"header" toml:"header" yaml:"header"`
	Body     string            `json:"body" toml:"body" yaml:"body"`
	Timeout  int               `json:"timeout" toml:"timeout" yaml:"timeout"`
	ProxyURL string            `json:"proxy_url" toml:"proxy_url" yaml:"proxy_url"`
}

type CmdRequestConfig struct {
	Exec    string `json:"exec" toml:"exec" yaml:"exec"`
	Timeout int    `json:"timeout" toml:"timeout" yaml:"timeout"`
	Shell   bool   `json:"shell" toml:"shell" yaml:"shell"`
}

type ParseConfig struct {
	Method  string `json:"method" toml:"method" yaml:"method"`
	Pattern string `json:"pattern" toml:"pattern" yaml:"pattern"`
}

type MappingConfig struct {
	Name  string            `json:"name" toml:"name" yaml:"name"`
	Value string            `json:"value" toml:"value" yaml:"value"`
	Tags  map[string]string `json:"tags" toml:"tags" yaml:"tags"`
}
