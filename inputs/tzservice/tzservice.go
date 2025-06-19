package tzservice

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"flashcat.cloud/categraf/config"
	"flashcat.cloud/categraf/inputs"
	"flashcat.cloud/categraf/inputs/filecount"
	"flashcat.cloud/categraf/types"
	"github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	inputName            = "tzservice"
	metricPrefix         = "service"
	defaultValue float64 = 0
)

type TZServiceInput struct {
	config.PluginConfig
	ServiceConfig ServiceConfig   `json:"service" yaml:"service" toml:"service"`
	Log           LogConfig       `json:"log" yaml:"log" toml:"log"`
	Collects      []CollectConfig `json:"collect" yaml:"collect" toml:"collect"`

	cleans               []func()
	logger               *logrus.Logger
	gameServiceInfoCache *GameServiceInfoCache
	serviceMatcher       *regexp.Regexp
	procs                map[string]*process.Process
}

func getProcessHash(p *process.Process) string {
	m := md5.New()
	ct, _ := p.CreateTime()
	m.Write(fmt.Appendf(nil, "%d|%d", p.Pid, ct))
	return hex.EncodeToString(m.Sum(nil))
}

func init() {
	inputs.Add(inputName, func() inputs.Input {
		return &TZServiceInput{}
	})
}

func (pt *TZServiceInput) Init() error {
	pt.initLogger()
	if pt.ServiceConfig.ProcessFilter != "" {
		pt.serviceMatcher = regexp.MustCompile(pt.ServiceConfig.ProcessFilter)
	}
	pt.initGameServiceInfoCache()
	pt.procs = make(map[string]*process.Process)
	return nil
}

func (pt *TZServiceInput) initLogger() {
	var writer io.Writer
	if pt.Log.Path != "" {
		leaveDays := pt.Log.LeaveDays
		if leaveDays == 0 {
			leaveDays = 7
		}
		out := &lumberjack.Logger{
			Filename: pt.Log.Path,
			MaxAge:   leaveDays,
			Compress: true,
		}
		pt.cleans = append(pt.cleans, func() {
			_ = out.Close()
		})
		if !pt.Log.Stdout {
			writer = out
		} else {
			writer = io.MultiWriter(out, os.Stdout)
		}
	} else {
		writer = os.Stdout
	}

	logger := logrus.New()
	logger.Out = writer

	var level logrus.Level
	if pt.Log.Level != "" {
		var err error
		level, err = logrus.ParseLevel(pt.Log.Level)
		if err != nil {
			fmt.Println(err)
			level = logrus.InfoLevel
		}
	} else {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	if pt.Log.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	pt.logger = logger
}

func (pt *TZServiceInput) initGameServiceInfoCache() {
	var provider GameServiceInfoProvider
	if pt.ServiceConfig.HttpProvider != nil {
		provider = NewHttpGameServiceInfoProvider(pt.ServiceConfig.HttpProvider)
	} else if pt.ServiceConfig.FileProvider != nil {
		provider = NewFileGameServiceInfoProvider(pt.ServiceConfig.FileProvider)
	} else if pt.ServiceConfig.RedisProvider != nil {
		provider = NewRedisGameServiceInfoProvider(pt.ServiceConfig.RedisProvider)
	} else if pt.ServiceConfig.CmdbProvider != nil {
		provider = NewCmdbGameServiceInfoProvider(pt.ServiceConfig.CmdbProvider)
	} else {
		panic("游戏服信息接口配置不存在")
	}

	var cacheTTL time.Duration
	if pt.ServiceConfig.CacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	} else {
		cacheTTL = time.Duration(pt.ServiceConfig.CacheTTL) * time.Second
	}
	pt.gameServiceInfoCache = NewGameServiceInfoCache(provider, cacheTTL, pt.logger)
}

func (pt *TZServiceInput) Drop() {
	closer, ok := pt.logger.Out.(io.Closer)
	if ok {
		_ = closer.Close()
	}
	for _, f := range pt.cleans {
		f()
	}
}

func (pt *TZServiceInput) Clone() inputs.Input {
	return &TZServiceInput{
		cleans:               pt.cleans,
		logger:               pt.logger,
		gameServiceInfoCache: pt.gameServiceInfoCache,
		serviceMatcher:       pt.serviceMatcher,
	}
}

func (pt *TZServiceInput) Name() string {
	return inputName
}

func (pt *TZServiceInput) GetInstances() []inputs.Instance {
	if len(pt.Collects) == 0 {
		return nil
	}
	ins := make([]inputs.Instance, len(pt.Collects))
	for i := 0; i < len(pt.Collects); i++ {
		cl := &pt.Collects[i]
		name := cl.Name
		if name == "" {
			name = fmt.Sprintf("collect_%d", i+1)
		}
		ins[i] = &Instance{
			CollectConfig:        cl,
			gameServiceInfoCache: pt.gameServiceInfoCache,
			logger:               pt.logger.WithField("collect", name),
		}
	}
	return ins
}

func (pt *TZServiceInput) findGameServerProcesses(baseDir string, services []*GameServiceInfo, isService func(string) bool) (map[string]*process.Process, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}
	ps := make(map[string]*process.Process)
	for _, p := range processes {
		status, _ := p.Status()
		if status == "" || status == "Z" {
			continue
		}
		cwd, err := p.Cwd()
		if err != nil {
			pt.logger.WithError(err).Error("获取进程工作目录失败")
			continue
		}
		if !strings.HasPrefix(cwd, baseDir) {
			continue
		}
		// check by global regexp
		cmd, err := p.Cmdline()
		if err != nil {
			pt.logger.WithError(err).Info("获取进程启动命令行失败")
			continue
		}
		if !isService(cmd) {
			continue
		}
		key := filepath.Base(cwd)
		ps[key] = p
	}
	pm := make(map[string]*process.Process)
	for _, s := range services {
		id := s.ServiceId
		pc := ps[id]
		if pc != nil {
			cmd, err := pc.Cmdline()
			if err != nil {
				pt.logger.WithError(err).Error("获取进程启动命令行失败")
				pm[id] = nil
				continue
			}
			// service has been assigned a command string, just check it
			if s.CheckCmd != "" && !strings.Contains(cmd, s.CheckCmd) {
				continue
			}
			pm[id] = pc
		} else {
			pm[id] = nil
		}
	}
	return pm, nil
}

func (pt *TZServiceInput) findOtherProcesses(services []*GameServiceInfo, isService func(string) bool) (map[string][]*process.Process, error) {
	ps, err := process.Processes()
	if err != nil {
		return nil, err
	}
	find := func(p *process.Process) *GameServiceInfo {
		exe, _ := p.Exe()
		cmd, _ := p.Cmdline()
		cwd, _ := p.Cwd()
		for _, info := range services {
			_exe, ok := info.Extra["exe"].(string)
			if ok && exe != _exe {
				continue
			}
			_cwd, ok := info.Extra["cwd"].(string)
			if ok && _cwd != cwd {
				continue
			}
			if info.CheckCmd != "" && !strings.Contains(cmd, info.CheckCmd) {
				continue
			}
			return info
		}
		return nil
	}
	pm := map[string][]*process.Process{}
	for _, p := range ps {
		status, _ := p.Status()
		if status == "" || status == "Z" {
			continue
		}
		info := find(p)
		if info != nil {
			pm[info.ServiceId] = append(pm[info.ServiceId], p)
		}
	}

	return pm, nil
}

func (pt *TZServiceInput) isService(cmd string) bool {
	if pt.serviceMatcher == nil {
		return true
	}
	return pt.serviceMatcher.MatchString(cmd)
}

func (pt *TZServiceInput) Gather(sl *types.SampleList) {
	infos := pt.gameServiceInfoCache.GetGameServiceInfo()
	wait := &sync.WaitGroup{}
	ids := make(map[string]struct{})
	if pt.ServiceConfig.Mode == 1 {
		pss, err := pt.findOtherProcesses(infos, pt.isService)
		if err != nil {
			pt.logger.WithError(err).Error("查找进程失败")
			return
		}
		for _, info := range infos {
			ps := pss[info.ServiceId]
			size := len(ps)
			wait.Add(size)
			sl.PushSample(metricPrefix, "num_proc", float64(size), info.MetricTags())
			for _, p := range ps {
				id, p := pt.getOrSetProcess(p)
				ids[id] = struct{}{}
				go pt.gather(wait, sl, info, p)
			}
		}
	} else {
		ps, err := pt.findGameServerProcesses(pt.ServiceConfig.BaseDir, infos, pt.isService)
		if err != nil {
			pt.logger.WithError(err).Error("查找进程失败")
			return
		}
		wait.Add(len(infos))
		for _, info := range infos {
			id, p := pt.getOrSetProcess(ps[info.ServiceId])
			if p == nil {
				sl.PushSample(metricPrefix, "num_proc", 0, info.MetricTags())
				pt.logger.WithField("service", info.ServiceId).Info("进程不存在")
				continue
			}
			ids[id] = struct{}{}
			sl.PushSample(metricPrefix, "num_proc", 1, info.MetricTags())
			go pt.gather(wait, sl, info, p)
		}
	}
	wait.Wait()
	pt.clearNoExistsProcess(ids)
}

func (pt *TZServiceInput) getOrSetProcess(p *process.Process) (string, *process.Process) {
	id := getProcessHash(p)
	old, has := pt.procs[id]
	if has && old != nil {
		return id, old
	}
	pt.procs[id] = p
	return id, p
}

// 清除不存在的进程
func (pt *TZServiceInput) clearNoExistsProcess(exists map[string]struct{}) {
	var deleted []string
	for id := range pt.procs {
		if _, ok := exists[id]; !ok {
			deleted = append(deleted, id)
		}
	}
	for _, id := range deleted {
		delete(pt.procs, id)
	}
}

// 采集单个服务状态
func (pt *TZServiceInput) gather(wait *sync.WaitGroup, sl *types.SampleList, serviceInfo *GameServiceInfo, p *process.Process) {
	defer wait.Done()

	logger := pt.logger.WithField("service", serviceInfo.ServiceId)
	pt.gameServiceInfoCache.SetServicePid(serviceInfo.ServiceId, 0)

	tags := serviceInfo.MetricTags()

	defer func() {
		err := recover()
		if err != nil {
			logger.WithField("panic", err).Error("采集单个服务失败")
		}
	}()

	tags["pid"] = strconv.Itoa(int(p.Pid))
	pt.sampleProcess(sl, logger, p, serviceInfo, tags)
	if !pt.ServiceConfig.DisableFileCount {
		dir := path.Join(pt.ServiceConfig.BaseDir, serviceInfo.ServiceId)
		pt.sampleFileCount(sl, logger, p, dir, tags)
	}
	if serviceInfo.WsPort != 0 {
		pt.sampleWebsocket(sl, logger, metricPrefix, serviceInfo, tags)
	}
}

// 采集进程信息
func (pt *TZServiceInput) sampleProcess(sl *types.SampleList, logger *logrus.Entry, proc *process.Process, serviceInfo *GameServiceInfo, tags map[string]string) {
	state := GetProcessState(logger, proc)
	if state == nil {
		return
	}
	pt.gameServiceInfoCache.SetServicePid(serviceInfo.ServiceId, state.Pid)
	numFds, err := proc.NumFDs()
	if err != nil {
		logger.WithError(err).Error("读取描述符数量失败")
	}
	nios, err := proc.NetIOCountersWithContext(context.Background(), false)
	if err != nil {
		logger.WithError(err).Error("读取网络IO失败")
	}
	recv, sent := 0, 0
	for _, io := range nios {
		recv += int(io.BytesRecv)
		sent += int(io.BytesSent)
	}

	fields := map[string]interface{}{
		"memory_used":     float64(state.MemoryInfo.RSS),
		"cpu_used":        state.CpuPercent,
		"elapsed_seconds": state.ElapsedTime,
		"num_fds":         float64(numFds),
		"net_io_sent":     sent,
		"net_io_recv":     recv,
	}
	sl.PushSamples(metricPrefix, fields, tags)
}

func (pt *TZServiceInput) sampleFileCount(sl *types.SampleList, logger *logrus.Entry, proc *process.Process, dir string, tags map[string]string) {
	fi := filecount.Instance{
		Directories: []string{dir},
	}
	err := fi.Init()
	if err != nil {
		logger.WithError(err).Error("读取文件数量失败")
		return
	}
	fi.SetTag(tags)
	fi.SetPrefix(metricPrefix)
	fi.Gather(sl)
}

func (pt *TZServiceInput) sampleWebsocket(sl *types.SampleList, logger *logrus.Entry, prefix string, serviceInfo *GameServiceInfo, tags map[string]string) {
	const metric = "ws_status"
	reqURL, err := renderTpl(pt.ServiceConfig.WsURL, serviceInfo)
	if err != nil {
		logger.WithError(err).Error("链接模板解析失败")
		return
	}
	var status float64
	ok := pt.websocketCheck(reqURL)
	if ok {
		status = 1
	}
	sl.PushSample(prefix, metric, status, tags)
}

var httpTransport = &http.Transport{
	DisableKeepAlives: true,
}

func (pt *TZServiceInput) websocketCheck(url string) bool {
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	client := &http.Client{
		Timeout:   time.Second,
		Transport: httpTransport,
	}
	resp, err := client.Do(req)
	if err != nil {
		pt.logger.WithError(err).Error("check websocket ", url, " ", resp.Status)
		return false
	}
	_ = resp.Body.Close()
	if resp.StatusCode == 101 {
		return true
	}
	pt.logger.WithField("url", url).WithField("status", resp.Status).Error("check websocket failed")
	return false
}
