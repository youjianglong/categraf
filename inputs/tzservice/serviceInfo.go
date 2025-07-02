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
	"strings"
	"sync"
	"time"

	"flashcat.cloud/categraf/config"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// serviceInfo 服务信息
type serviceInfo struct {
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
	Extra         H      `json:"extra,omitempty"`
}

func (i *serviceInfo) MetricTags() S {
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

type ServiceInfoProvider interface {
	Name() string                                     // 提供者名称
	Mode() int8                                       // 匹配模式
	GetServiceInfo(ip string) ([]*serviceInfo, error) // 获取游戏服务信息
}

type Zero = struct{}

type ServiceInfoCache struct {
	providers   []ServiceInfoProvider
	ttl         time.Duration
	syncCh      chan Zero
	logger      *logrus.Logger
	services0   []*serviceInfo
	services1   []*serviceInfo
	infoLock    sync.RWMutex
	last        time.Time
	procNum     map[string]int
	procNumLock sync.RWMutex
}

func NewServiceInfoCache(providers []ServiceInfoProvider, ttl time.Duration, logger *logrus.Logger) *ServiceInfoCache {
	c := &ServiceInfoCache{
		providers: providers,
		ttl:       ttl,
		syncCh:    make(chan Zero),
		logger:    logger,
		procNum:   make(map[string]int),
	}
	go c.periodicSync()
	return c
}

func (c *ServiceInfoCache) GetServiceInfo0() []*serviceInfo {
	c.syncCh <- Zero{}
	c.infoLock.RLock()
	defer c.infoLock.RUnlock()
	return c.services0
}

func (c *ServiceInfoCache) GetServiceInfo1() []*serviceInfo {
	c.syncCh <- Zero{}
	c.infoLock.RLock()
	defer c.infoLock.RUnlock()
	return c.services1
}

func (c *ServiceInfoCache) GetAvailServiceInfo() []*serviceInfo {
	infos0 := c.GetServiceInfo0()
	infos1 := c.GetServiceInfo1()
	c.procNumLock.RLock()
	defer c.procNumLock.RUnlock()
	ret := make([]*serviceInfo, 0, len(infos0)+len(infos1))
	for _, info := range infos0 {
		if c.procNum[info.ServiceId] > 0 {
			ret = append(ret, info)
		}
	}
	for _, info := range infos1 {
		if c.procNum[info.ServiceId] > 0 {
			ret = append(ret, info)
		}
	}
	return ret
}

func (c *ServiceInfoCache) SetProcNum(procNum map[string]int) {
	c.procNumLock.Lock()
	defer c.procNumLock.Unlock()
	c.procNum = procNum
}

func (c *ServiceInfoCache) Sync() {
	c.infoLock.Lock()
	defer func() {
		c.infoLock.Unlock()
		re := recover()
		if re != nil {
			stacks := GetStacks(1)
			c.logger.Errorf("同步服务信息异常: %v\n  %s", re, strings.Join(stacks, "\n  "))
		}
	}()
	c.logger.Debug("开始同步服务信息")
	var services0, services1 []*serviceInfo
	for _, provider := range c.providers {
		logger := c.logger.WithField("provider", provider.Name())
		logger.Debug("syncing ...")
		infos, err := provider.GetServiceInfo(GetLocalIP())
		if err != nil {
			logger.Error("同步失败: " + err.Error())
			return
		}
		if provider.Mode() == 1 {
			services1 = append(services1, infos...)
		} else {
			services0 = append(services0, infos...)
		}
	}
	c.services0 = services0
	c.services1 = services1
	c.last = time.Now()
}

func (c *ServiceInfoCache) periodicSync() {
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

func NewHttpGameServiceInfoProvider(cfg *HttpServiceInfoProviderConfig) ServiceInfoProvider {
	p := &HttpGameServiceInfoProvider{
		cfg: cfg,
	}
	return p
}

func (p *HttpGameServiceInfoProvider) Name() string {
	return "http"
}

func (p *HttpGameServiceInfoProvider) Mode() int8 {
	return p.cfg.Mode
}

func (p *HttpGameServiceInfoProvider) GetServiceInfo(ip string) ([]*serviceInfo, error) {
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
	var infos []*serviceInfo
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

func (p *FileGameServiceInfoProvider) Name() string {
	return "file"
}

func (p *FileGameServiceInfoProvider) Mode() int8 {
	return p.cfg.Mode
}

func (p *FileGameServiceInfoProvider) GetServiceInfo(ip string) ([]*serviceInfo, error) {
	list := make([]*serviceInfo, 0)
	res := make([]*serviceInfo, 0)
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

func (p *RedisGameServiceInfoProvider) Name() string {
	return "redis"
}

func (p *RedisGameServiceInfoProvider) Mode() int8 {
	return p.cfg.Mode
}

func (p *RedisGameServiceInfoProvider) Init() {
	rdb := redis.NewClient(&redis.Options{
		Addr:     p.cfg.Addr,
		Password: p.cfg.Password,
		DB:       p.cfg.DB,
	})
	p.rdb = rdb
}

func (p *RedisGameServiceInfoProvider) GetServiceInfo(ip string) ([]*serviceInfo, error) {
	res := make([]*serviceInfo, 0)
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

func (CmdbGameServiceInfoProvider) Name() string {
	return "cmdb"
}

func (p *CmdbGameServiceInfoProvider) Mode() int8 {
	return 1 // 仅支持模式
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

func getStr(v H, key string) string {
	if v == nil {
		return ""
	}
	s, _ := v[key].(string)
	return s
}

func (*CmdbGameServiceInfoProvider) toGameServiceInfo(res *CmdbResource) *serviceInfo {
	info := &serviceInfo{
		Name:        getStr(res.Data, "service_name"),
		ServiceId:   res.Name, // name是cmdb资源唯一名称
		ServiceType: getStr(res.Data, "service_type"),
		PrivateIP:   getStr(res.Data, "private_ip"),
		CheckCmd:    getStr(res.Data, "check_cmd"),
		Extra:       H{},
	}
	copyExists(info.Extra, res.Data, "exe", "cwd")
	return info
}

func (p *CmdbGameServiceInfoProvider) getProcesses() ([]*serviceInfo, error) {
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

	infos := make([]*serviceInfo, 0, len(response.Data.Resources))
	for _, res := range response.Data.Resources {
		info := p.toGameServiceInfo(res)
		infos = append(infos, info)
	}

	return infos, nil
}

func (p *CmdbGameServiceInfoProvider) GetServiceInfo(ip string) ([]*serviceInfo, error) {
	return p.getProcesses()
}
