package tzservice

import "flashcat.cloud/categraf/config"

type ServiceConfig struct {
	Mode             int                             `json:"mode" yaml:"mode" toml:"mode"` // 服务模式，0=连服模式、1=其它服匹配模式
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
}
type FileServiceInfoProviderConfig struct {
	Path string `json:"path" yaml:"path" toml:"path"`
}

type RedisServiceInfoProviderConfig struct {
	Addr     string `json:"addr" yaml:"addr" toml:"addr"`
	Password string `json:"password" yaml:"password" toml:"password"`
	DB       int    `json:"db" yaml:"db" toml:"db"`
}

type CmdbServiceInfoProviderConfig struct {
	BaseURL   string `json:"base_url" yaml:"base_url" toml:"base_url"`
	AccessKey string `json:"access_key" yaml:"access_key" toml:"access_key"`
	SecretKey string `json:"secret_key" yaml:"secret_key" toml:"secret_key"`
	Model     string `json:"model" yaml:"model" toml:"model"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level     string `json:"level" yaml:"level" toml:"level"`
	Stdout    bool   `json:"stdout" yaml:"stdout" toml:"stdout"`
	Format    string `json:"format" yaml:"format" toml:"format"`
	Path      string `json:"path" yaml:"path" toml:"path"`
	LeaveDays int    `json:"leave_days" yaml:"leave_days" toml:"leave_days"`
}

// CollectConfig 采集配置
type CollectConfig struct {
	config.InstanceConfig
	Name     string             `json:"name" toml:"name" yaml:"name"`
	Iterate  bool               `json:"iterate" toml:"iterate" yaml:"iterate"`
	Parallel bool               `json:"parallel" toml:"parallel" yaml:"parallel"`
	Http     *HttpRequestConfig `json:"http" toml:"http" yaml:"http"`
	Cmd      *CmdRequestConfig  `json:"cmd" toml:"cmd" yaml:"cmd"`
	Parse    ParseConfig        `json:"parse" toml:"parse" yaml:"parse"`
	Mappings []MappingConfig    `json:"mapping" toml:"mapping" yaml:"mapping"`
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
