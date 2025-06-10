package procscan

import (
	client "go.etcd.io/etcd/client/v3"
)

type LeaseID = client.LeaseID

type EtcdConfig struct {
	Endpoints []string `json:"endpoints" toml:"endpoints"`
	KeyPrefix string   `json:"key_prefix" toml:"key_prefix"`
	TTL       int64    `json:"ttl" toml:"ttl"`
}

type EtcdCLI struct {
	cfg *EtcdConfig
	cli *client.Client
}

func NewEtcdCLI(cfg *EtcdConfig) (*EtcdCLI, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = 600
	}
	cli, err := client.New(client.Config{
		Endpoints: cfg.Endpoints,
	})
	if err != nil {
		return nil, err
	}
	return &EtcdCLI{cfg: cfg, cli: cli}, nil
}

func (e *EtcdCLI) Close() error {
	return e.cli.Close()
}

// Save 保存配置
func (e *EtcdCLI) Put(key string, data []byte, leaseID LeaseID) error {
	// 写入etcd,关联lease
	key = e.cfg.KeyPrefix + key
	var opts []client.OpOption
	if leaseID > 0 {
		opts = append(opts, client.WithLease(leaseID))
	}
	_, err := e.cli.Put(e.cli.Ctx(), key, string(data), opts...)
	return err
}

// 写入并保活
func (e *EtcdCLI) KeepAlive(key string, data []byte) (LeaseID, error) {
	// 创建lease
	resp, err := e.cli.Grant(e.cli.Ctx(), e.cfg.TTL)
	if err != nil {
		return 0, err
	}
	// 写入值,关联lease
	key = e.cfg.KeyPrefix + key
	_, err = e.cli.Put(e.cli.Ctx(), key, string(data), client.WithLease(resp.ID))
	if err != nil {
		return 0, err
	}
	// 保活
	ch, err := e.cli.KeepAlive(e.cli.Ctx(), resp.ID)
	if err != nil {
		return 0, err
	}
	go func() {
		for v := range ch {
			logf("keepAlive %d: %d\n", v.ID, v.TTL)
		}
	}()
	return resp.ID, nil
}

// GetValue 从etcd获取配置
func (e *EtcdCLI) Get(key string) ([]byte, error) {
	key = e.cfg.KeyPrefix + key
	resp, err := e.cli.Get(e.cli.Ctx(), key)
	if err != nil {
		return nil, err
	}

	if len(resp.Kvs) == 0 {
		return nil, nil
	}

	return resp.Kvs[0].Value, nil
}

// Watch 监听指定key的变化
func (e *EtcdCLI) Watch(key string, callback func([]byte)) {
	key = e.cfg.KeyPrefix + key
	ch := e.cli.Watch(e.cli.Ctx(), key)

	go func() {
		for wr := range ch {
			for _, ev := range wr.Events {
				// 如果是删除事件,传递空数据
				if ev.Type == client.EventTypeDelete {
					callback(nil)
					continue
				}

				// 获取过滤规则字符串
				callback(ev.Kv.Value)
			}
		}
	}()
}
