package tzservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"flashcat.cloud/categraf/pkg/httpx"
	"flashcat.cloud/categraf/types"
	"github.com/sirupsen/logrus"
)

type Instance struct {
	*CollectConfig
	gameServiceInfoCache *GameServiceInfoCache
	logger               *logrus.Entry
}

func (ins *Instance) Init() error {
	if ins.Http == nil && ins.Cmd == nil {
		return errors.New("http or cmd must be set")
	}
	if len(ins.Mappings) < 1 {
		return errors.New("mapping must be set")
	}
	return nil
}

func (ins *Instance) createHTTPClient(cfg *HttpRequestConfig) *http.Client {
	dialer := &net.Dialer{}

	client := httpx.CreateHTTPClient(httpx.TlsConfig(&tls.Config{InsecureSkipVerify: true}),
		httpx.NetDialer(dialer), httpx.Proxy(httpx.GetProxyFunc(cfg.ProxyURL)),
		httpx.Timeout(time.Duration(cfg.Timeout)*time.Second),
		httpx.DisableKeepAlives(true),
		httpx.FollowRedirects(false))

	return client
}

func (ins *Instance) httpRequest(cfg *HttpRequestConfig, target *GameServiceInfo) ([]byte, error) {
	reqURL, err := ins.renderTpl(cfg.URL, target)
	if err != nil {
		ins.logger.WithError(err).Error("链接模板解析失败")
		return nil, err
	}
	var body io.Reader
	if cfg.Body != "" {
		text, err := ins.renderTpl(cfg.Body, target)
		if err != nil {
			ins.logger.WithError(err).Error("body模板解析失败")
			return nil, err
		}
		body = strings.NewReader(text)
	}

	req, err := http.NewRequest(cfg.Method, reqURL, body)
	if err != nil {
		return nil, err
	}
	if cfg.Header != nil {
		for k, v := range cfg.Header {
			req.Header.Add(k, v)
		}
	}
	resp, err := ins.createHTTPClient(cfg).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (ins *Instance) cmdExec(cfg *CmdRequestConfig, target *GameServiceInfo) ([]byte, error) {
	cmdStr, err := ins.renderTpl(cfg.Exec, target)
	if err != nil {
		ins.logger.WithError(err).Error("命令行模板解析失败")
		return nil, err
	}
	name, args := ParseCmd(cmdStr, cfg.Shell)

	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	var cmd *exec.Cmd
	if cfg.Timeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, name, args...)
	} else {
		cmd = exec.Command(name, args...)
	}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	err = cmd.Run()
	if errBuf.Len() > 0 {
		ins.logger.Info("stderr: " + errBuf.String())
	}
	if err != nil {
		ins.logger.WithError(err).Error("执行命令失败")
		return nil, err
	}
	return outBuf.Bytes(), nil
}

func (ins *Instance) renderTpl(s string, data any) (string, error) {
	tpl, err := template.New("tpl").Funcs(tplFuncMap).Parse(s)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	err = tpl.Execute(buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderTpl(s string, data any) (string, error) {
	tpl, err := template.New("tpl").Funcs(tplFuncMap).Parse(s)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	err = tpl.Execute(buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (ins *Instance) ParseResult(cfg ParseConfig, data []byte) (result any, err error) {
	if cfg.Method == "json" {
		err = json.Unmarshal(data, &result)
		return
	} else if cfg.Method == "regex" {
		p, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return nil, err
		}
		result = p.FindStringSubmatch(string(data))
	}
	return
}

func (ins *Instance) gather(sl *types.SampleList, t *GameServiceInfo, query func(info *GameServiceInfo) ([]byte, error)) {
	data, err := query(t)
	if err != nil {
		ins.logger.WithError(err).Warn("采集失败")
		return
	}
	result, err := ins.ParseResult(ins.Parse, data)
	if err != nil {
		ins.logger.WithError(err).Warn("解析失败")
		return
	}
	for _, e := range ins.Mappings {
		ins.pushSample(sl, t, e, result)
	}
}

func (ins *Instance) pushSample(sl *types.SampleList, info *GameServiceInfo, mapping MappingConfig, result any) {
	var value float64
	var tags map[string]string
	if info != nil {
		tags = info.MetricTags()
	} else {
		tags = make(map[string]string)
	}

	if mapping.Value == "" {
		value = defaultValue
	} else {
		v := PathGet(result, mapping.Value)
		if v == nil {
			ins.logger.Error("value path not found: " + mapping.Value)
			return
		}
		var ok bool
		value, ok = v.(float64)
		if !ok {
			var err error
			value, err = strconv.ParseFloat(fmt.Sprint(v), 64)
			if err != nil {
				ins.logger.WithError(err).Error("value parse error")
				return
			}
		}
	}

	for t, p := range mapping.Tags {
		handler := ""
		if strings.Contains(p, "|") {
			s := strings.SplitN(p, "|", 2)
			handler = s[1]
			p = s[0]
		}
		v := PathGet(result, p)
		if handler != "" {
			tpl := fmt.Sprintf("{{%s .}}", handler)
			s, err := ins.renderTpl(tpl, v)
			if err != nil {
				ins.logger.WithError(err).Error("tag handler error")
			}
			tags[t] = s
		} else {
			if v == nil {
				tags[t] = ""
			} else {
				tags[t] = fmt.Sprint(v)
			}
		}
	}

	sl.PushSample(metricPrefix, mapping.Name, value, tags)
}

func (ins *Instance) Gather(sl *types.SampleList) {
	cfg := ins.CollectConfig
	var query func(*GameServiceInfo) ([]byte, error)
	if cfg.Http != nil {
		query = func(si *GameServiceInfo) ([]byte, error) {
			return ins.httpRequest(cfg.Http, si)
		}
	} else if cfg.Cmd != nil {
		query = func(si *GameServiceInfo) ([]byte, error) {
			return ins.cmdExec(cfg.Cmd, si)
		}
	}

	if !cfg.Iterate {
		ins.gather(sl, nil, query)
		return
	}

	services := ins.gameServiceInfoCache.GetAvailGameServiceInfo()

	if cfg.Parallel {
		wait := new(sync.WaitGroup)
		wait.Add(len(services))
		for _, t := range services {
			go func(info *GameServiceInfo) {
				defer wait.Done()
				ins.gather(sl, info, query)
			}(t)
		}
		wait.Wait()
	} else {
		for _, info := range services {
			ins.gather(sl, info, query)
		}
	}
}
