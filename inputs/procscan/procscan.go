package procscan

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"sort"

	"log"

	"flashcat.cloud/categraf/config"
	"flashcat.cloud/categraf/inputs"
	"flashcat.cloud/categraf/pkg/netx"
	"flashcat.cloud/categraf/types"
)

const inputName = "procscan"

func init() {
	inputs.Add(inputName, func() inputs.Input {
		return &ProcScan{}
	})
}

type (
	ProcScan struct {
		config.PluginConfig
		Etcd EtcdConfig `json:"etcd" toml:"etcd"`
		CMDB CMDBConfig `json:"cmdb" toml:"cmdb"`
		Scan ScanConfig `json:"scan" toml:"scan"`

		cli      *EtcdCLI
		includes *TaggedFilter
		excludes *TaggedFilter
		putKey   string
		lastRev  string
		leaseID  LeaseID
	}
	CMDBConfig struct {
		Url   string `json:"url" toml:"url"`
		Token string `json:"token" toml:"token"`
	}
	ScanConfig struct {
		FilterKeyPrefix string `json:"filter_key_prefix" toml:"filter_key_prefix"` // 过滤规则前缀
		PutKeyPrefix    string `json:"put_key_prefix" toml:"put_key_prefix"`       // 保存进程信息前缀
	}
)

func (p *ProcScan) Name() string {
	return inputName
}

func (p *ProcScan) Init() error {
	if p.Etcd.KeyPrefix == "" {
		group := config.Config.Global.Labels["group"]
		if group != "" {
			p.Etcd.KeyPrefix = "pm/" + group + "/"
		}
	}

	cli, err := NewEtcdCLI(&p.Etcd)
	if err != nil {
		return err
	}
	p.cli = cli
	p.putKey = p.Scan.PutKeyPrefix + netx.LocalOutboundIP()

	p.loadFilters()

	return nil
}

func (p *ProcScan) Clone() inputs.Input {
	n := &ProcScan{}
	return n
}

func logf(format string, args ...any) {
	log.Printf("[procscan] "+format, args...)
}

func logln(args ...any) {
	log.Println("[procscan] " + fmt.Sprint(args...))
}

func (p *ProcScan) loadFilters() {
	if p.Scan.FilterKeyPrefix == "" {
		p.Scan.FilterKeyPrefix = "filter/"
	}
	includesKey := p.Scan.FilterKeyPrefix + "includes"
	excludesKey := p.Scan.FilterKeyPrefix + "excludes"
	includes, err := p.loadFilter(includesKey)
	if err == nil {
		p.includes = includes
	} else {
		logln(err)
	}
	excludes, err := p.loadFilter(excludesKey)
	if err == nil {
		p.excludes = excludes
	} else {
		logln(err)
	}
	p.cli.Watch(includesKey, func(data []byte) {
		if data == nil {
			p.includes = nil
			return
		}
		includes, err := ParseTaggedFilter(string(data))
		if err == nil {
			p.includes = includes
		} else {
			logln(err)
		}
	})
	p.cli.Watch(excludesKey, func(data []byte) {
		if data == nil {
			p.excludes = nil
			return
		}
		excludes, err := ParseTaggedFilter(string(data))
		if err == nil {
			p.excludes = excludes
		} else {
			logln(err)
		}
	})
}

func (p *ProcScan) loadFilter(key string) (*TaggedFilter, error) {
	rules, err := p.cli.Get(key)
	if err != nil {
		return nil, fmt.Errorf("get[%s]: %w", key, err)
	}
	filter, err := ParseTaggedFilter(string(rules))
	if err != nil {
		return nil, fmt.Errorf("parseIncludes: %w", err)
	}
	return filter, nil
}

func sumRev(data []byte) string {
	h := crc32.NewIEEE()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum32())
}

func (p *ProcScan) Gather(slist *types.SampleList) {
	processInfos, err := FilterProcesses(p.includes, p.excludes)
	if err != nil {
		logf("filterProcesses: %v", err)
		return
	}
	sort.Slice(processInfos, func(i, j int) bool {
		return processInfos[i].PID < processInfos[j].PID
	})
	data, _ := json.Marshal(processInfos)
	rev := sumRev(data)
	if p.lastRev == "" {
		p.leaseID, err = p.cli.KeepAlive(p.putKey, data)
	} else if p.lastRev != rev {
		err = p.cli.Put(p.putKey, data, p.leaseID)
	}
	if err != nil {
		logf("put: %v", err)
	}
	p.lastRev = rev
}
