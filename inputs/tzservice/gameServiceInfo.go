package tzservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// GameServiceInfo 游戏服务信息
type GameServiceInfo struct {
	Name          string `json:"name"`
	ServiceId     string `json:"service_id"`
	PrivateIP     string `json:"private_ip"`
	PortID        int    `json:"port_ip"`
	CreateTime    string `json:"create_time"`
	ServiceTypeID int    `json:"service_type_id"`
	ServiceType   string `json:"service_type"`
	ClusterID     int    `json:"cluster_id"`
	ClusterType   string `json:"cluster_type"`
	ClusterName   string `json:"cluster_name"`
	GameID        int    `json:"game_id"`
	GameName      string `json:"game_name"`
	CheckCmd      string `json:"check_cmd"`
	StatusApiPort int    `json:"status_api_port"`
	StatusApiPath string `json:"status_api_path"`
	FixID         string `json:"fix_id"`
	WsPort        int    `json:"ws_port"`
	WssPort       int    `json:"wss_port"`

	Extra H `json:"extra"`
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
		"game_id":      strconv.Itoa(i.GameID),
		"game_name":    i.GameName,
		"cluster_type": i.ClusterType,
		"cluster_name": i.ClusterName,
		"private_ip":   i.PrivateIP,
	}
	if i.ClusterID != 0 {
		tags["cluster_id"] = strconv.Itoa(i.ClusterID)
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
