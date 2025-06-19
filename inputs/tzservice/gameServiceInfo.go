package tzservice

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"flashcat.cloud/categraf/config"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// GameServiceInfo 游戏服务信息
type GameServiceInfo struct {
	Name          string `json:"name"`
	ServiceId     string `json:"service_id"`
	PrivateIP     string `json:"private_ip"`
	ServiceType   string `json:"service_type"`
	ServiceTypeID int    `json:"service_type_id,omitempty"`
	PortID        int    `json:"port_ip,omitempty"`
	CreateTime    string `json:"create_time,omitempty"`
	ClusterID     int    `json:"cluster_id,omitempty"`
	ClusterType   string `json:"cluster_type,omitempty"`
	ClusterName   string `json:"cluster_name,omitempty"`
	GameID        int    `json:"game_id,omitempty"`
	GameName      string `json:"game_name,omitempty"`
	CheckCmd      string `json:"check_cmd,omitempty"`
	StatusApiPort int    `json:"status_api_port,omitempty"`
	StatusApiPath string `json:"status_api_path,omitempty"`
	FixID         string `json:"fix_id,omitempty"`
	WsPort        int    `json:"ws_port,omitempty"`
	WssPort       int    `json:"wss_port,omitempty"`

	Extra H `json:"extra,omitempty"`
}

func (i *GameServiceInfo) MetricTags() S {
	sid := i.ServiceId
	if i.FixID != "" {
		sid = i.FixID
	}
	tags := S{
		"service_id":   sid,
		"service_name": i.Name,
		"service_type": i.ServiceType,
		"private_ip":   i.PrivateIP,
	}
	if i.ClusterID != 0 {
		tags["cluster_id"] = strconv.Itoa(i.ClusterID)
	}
	if i.GameID != 0 {
		tags["game_id"] = strconv.Itoa(i.GameID)
		tags["game_name"] = i.GameName
	}
	if i.ClusterType != "" {
		tags["cluster_type"] = i.ClusterType
		tags["cluster_name"] = i.ClusterName
	}
	return tags
}

type GameServiceInfoProvider interface {
	GetGameServiceInfo(ip string) ([]*GameServiceInfo, error)
}

type Zero struct{}

type GameServiceInfoCache struct {
	provider GameServiceInfoProvider
	ttl      time.Duration
	syncCh   chan Zero
	logger   *logrus.Logger
	infos    []*GameServiceInfo
	infoLock sync.RWMutex
	last     time.Time
	pidMap   map[string]int32
	pidLock  sync.RWMutex
}

func NewGameServiceInfoCache(provider GameServiceInfoProvider, ttl time.Duration, logger *logrus.Logger) *GameServiceInfoCache {
	c := &GameServiceInfoCache{
		provider: provider,
		ttl:      ttl,
		syncCh:   make(chan Zero),
		logger:   logger,
		pidMap:   make(map[string]int32),
	}
	go c.periodicSync()
	return c
}

func (c *GameServiceInfoCache) GetGameServiceInfo() []*GameServiceInfo {
	c.syncCh <- Zero{}
	c.infoLock.RLock()
	defer c.infoLock.RUnlock()
	return c.infos
}

func (c *GameServiceInfoCache) GetAvailGameServiceInfo() []*GameServiceInfo {
	infos := c.GetGameServiceInfo()
	c.pidLock.RLock()
	defer c.pidLock.RUnlock()
	ret := make([]*GameServiceInfo, 0, len(infos))
	for _, info := range infos {
		if c.pidMap[info.ServiceId] > 0 {
			ret = append(ret, info)
		}
	}
	return ret
}

func (c *GameServiceInfoCache) SetServicePid(serviceId string, pid int32) {
	c.pidLock.Lock()
	defer c.pidLock.Unlock()
	c.pidMap[serviceId] = pid
}

func (c *GameServiceInfoCache) Sync() {
	c.infoLock.Lock()
	defer c.infoLock.Unlock()
	c.logger.Info("开始同步游戏服务信息")
	infos, err := c.provider.GetGameServiceInfo(GetLocalIP())
	if err != nil {
		c.logger.WithError(err).Error("同步失败")
		return
	}
	b, _ := json.Marshal(infos)
	c.logger.WithField("json", string(b)).Debug("同步结果")
	c.infos = infos
	c.last = time.Now()
}

func (c *GameServiceInfoCache) periodicSync() {
	for {
		if c.last.IsZero() || time.Since(c.last) > c.ttl {
			c.Sync()
		}
		<-c.syncCh
	}
}

type HttpGameServiceInfoProvider struct {
	cfg *HttpServiceInfoProviderConfig
}

func NewHttpGameServiceInfoProvider(cfg *HttpServiceInfoProviderConfig) GameServiceInfoProvider {
	p := &HttpGameServiceInfoProvider{
		cfg: cfg,
	}
	return p
}

func (p *HttpGameServiceInfoProvider) GetGameServiceInfo(ip string) ([]*GameServiceInfo, error) {
	now := time.Now()
	query := url.Values{}
	ts := now.Format("20060102150405")
	query.Add("ip", ip)
	query.Add("ts", ts)
	query.Add("sign", Md5Str(ip+ts+p.cfg.SecretKey))
	reqUrl := p.cfg.ApiUrl + "?" + query.Encode()

	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "http请求无效")
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithMessage(err, "http请求失败")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessage(err, "http请求失败")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http请求失败 status code(%d): %v", resp.StatusCode, string(data))
	}
	var infos []*GameServiceInfo
	err = json.Unmarshal(data, &infos)
	if err != nil {
		return nil, errors.WithMessage(err, "json解析失败")
	}

	return infos, nil
}

type FileGameServiceInfoProvider struct {
	cfg *FileServiceInfoProviderConfig
}

func NewFileGameServiceInfoProvider(cfg *FileServiceInfoProviderConfig) *FileGameServiceInfoProvider {
	return &FileGameServiceInfoProvider{
		cfg: cfg,
	}
}

func (p *FileGameServiceInfoProvider) GetGameServiceInfo(ip string) ([]*GameServiceInfo, error) {
	list := make([]*GameServiceInfo, 0)
	res := make([]*GameServiceInfo, 0)
	data, err := os.ReadFile(p.cfg.Path)
	if err != nil {
		return res, err
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return res, err
	}
	for _, info := range list {
		if info.PrivateIP == ip {
			res = append(res, info)
		}
	}
	return res, nil
}

type RedisGameServiceInfoProvider struct {
	cfg *RedisServiceInfoProviderConfig
	rdb *redis.Client
}

func NewRedisGameServiceInfoProvider(cfg *RedisServiceInfoProviderConfig) *RedisGameServiceInfoProvider {
	p := &RedisGameServiceInfoProvider{
		cfg: cfg,
	}
	p.Init()
	return p
}

func (p *RedisGameServiceInfoProvider) Init() {
	rdb := redis.NewClient(&redis.Options{
		Addr:     p.cfg.Addr,
		Password: p.cfg.Password,
		DB:       p.cfg.DB,
	})
	p.rdb = rdb
}

func (p *RedisGameServiceInfoProvider) GetGameServiceInfo(ip string) ([]*GameServiceInfo, error) {
	res := make([]*GameServiceInfo, 0)
	redisKey := fmt.Sprintf("serviceInfo:%s", ip)
	data, err := p.rdb.Get(context.Background(), redisKey).Result()
	if err == redis.Nil {
		return res, nil
	}
	err = json.Unmarshal([]byte(data), &res)
	if err != nil {
		return res, err
	}
	return res, nil
}

type CmdbGameServiceInfoProvider struct {
	cfg    *CmdbServiceInfoProviderConfig
	client *http.Client
}

type CmdbResource struct {
	ID       int64          `json:"id"`
	Name     string         `json:"name"`
	ModelUID string         `json:"model_uid"`
	Data     map[string]any `json:"data"`
}

type CmdbResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Resources []*CmdbResource `json:"resources"`
		Total     int64           `json:"total"`
	} `json:"data"`
}

func NewCmdbGameServiceInfoProvider(cfg *CmdbServiceInfoProviderConfig) *CmdbGameServiceInfoProvider {
	if cfg.ProjectCode == "" {
		cfg.ProjectCode = config.Config.Global.Labels["group"]
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	return &CmdbGameServiceInfoProvider{cfg: cfg, client: client}
}

func (*CmdbGameServiceInfoProvider) sign(secretKey string, urlPath string, ts string) string {
	h := hmac.New(md5.New, []byte(secretKey))
	_, _ = h.Write([]byte(ts + urlPath))
	return hex.EncodeToString(h.Sum(nil))
}

func copyExists(dst, src H, keys ...string) {
	for _, key := range keys {
		v, ok := src[key]
		if ok {
			dst[key] = v
		}
	}
}

func (*CmdbGameServiceInfoProvider) toGameServiceInfo(res *CmdbResource) *GameServiceInfo {
	info := &GameServiceInfo{
		Name:        res.Name,
		ServiceId:   res.Data["service_id"].(string),
		ServiceType: res.Data["service_type"].(string),
		PrivateIP:   res.Data["private_ip"].(string),
		CheckCmd:    res.Data["check_cmd"].(string),
		Extra:       H{},
	}
	copyExists(info.Extra, res.Data, "exe", "cwd")
	return info
}

func (p *CmdbGameServiceInfoProvider) getProcesses() ([]*GameServiceInfo, error) {
	path := "/oapi/resource/find"
	url := p.cfg.BaseURL + path
	filters := H{
		"private_ip": GetLocalIP(),
		"status":     0,
	}
	if p.cfg.ProjectCode != "" {
		filters["project_code"] = p.cfg.ProjectCode
	}
	params := H{
		"model_uid": p.cfg.Model,
		"filters":   filters,
	}
	data, _ := json.Marshal(params)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	auth := fmt.Sprintf("Bearer %s/%s/%s", ts, p.cfg.AccessKey, p.sign(p.cfg.SecretKey, path, ts))
	req.Header.Set("Authorization", auth)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts: %w", err)
	}
	defer resp.Body.Close()

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	response := &CmdbResp{}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Code != 0 {
		return nil, fmt.Errorf("failed to fetch hosts: %s", response.Msg)
	}

	infos := make([]*GameServiceInfo, 0, len(response.Data.Resources))
	for _, res := range response.Data.Resources {
		info := p.toGameServiceInfo(res)
		infos = append(infos, info)
	}

	return infos, nil
}

func (p *CmdbGameServiceInfoProvider) GetGameServiceInfo(ip string) ([]*GameServiceInfo, error) {
	return p.getProcesses()
}
