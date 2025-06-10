package procscan

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/shirou/gopsutil/process"
)

type ProcessInfo struct {
	PID     int32  `json:"pid"`     // 进程ID
	PPID    int32  `json:"ppid"`    // 父进程ID
	Exe     string `json:"exe"`     // 可执行文件路径
	Cmdline string `json:"cmdline"` // 命令行参数
	Cwd     string `json:"cwd"`     // 当前工作目录
}

type ProcessState struct {
	PID         int32                   `json:"pid"`
	MemoryInfo  *process.MemoryInfoStat `json:"memory_info"`
	CpuPercent  float64                 `json:"cpu_percent"`
	ElapsedTime int64                   `json:"elapsed_time"`
	NumFDs      int32                   `json:"num_fds"`
	NetSent     uint64                  `json:"net_sent"`
	NetRecv     uint64                  `json:"net_recv"`
}

func GetProcessInfo(p *process.Process) (*ProcessInfo, error) {
	info := &ProcessInfo{}
	info.PID = p.Pid

	var err error
	info.Exe, err = p.Exe()
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("exe: %w", err)
	}
	info.Cwd, err = p.Cwd()
	if err != nil {
		return nil, fmt.Errorf("cwd: %w", err)
	}
	info.PPID, err = p.Ppid()
	if err != nil {
		return nil, fmt.Errorf("ppid: %w", err)
	}
	info.Cmdline, err = p.Cmdline()
	if err != nil {
		return nil, fmt.Errorf("cmdline: %w", err)
	}

	return info, nil
}

func GetProcessState(p *process.Process) (*ProcessState, error) {
	memInfo, err := p.MemoryInfo()
	if err != nil {
		return nil, fmt.Errorf("memoryInfo: %w", err)
	}
	cpuPercent, err := p.Percent(time.Duration(0))
	if err != nil {
		return nil, fmt.Errorf("percent: %w", err)
	}
	createTime, err := p.CreateTime()
	if err != nil {
		return nil, fmt.Errorf("createTime: %w", err)
	}
	numFds, err := p.NumFDs()
	if err != nil {
		return nil, fmt.Errorf("mumFDs: %w", err)
	}
	ios, err := p.NetIOCountersWithContext(context.Background(), false)
	if err != nil {
		return nil, fmt.Errorf("netIOCounters: %w", err)
	}
	var recv, sent uint64
	for _, io := range ios {
		recv += io.BytesRecv
		sent += io.BytesSent
	}
	state := &ProcessState{
		PID:         p.Pid,
		MemoryInfo:  memInfo,
		CpuPercent:  float64(int(cpuPercent*10000)) / 10000,
		ElapsedTime: time.Now().Unix() - (createTime / 1000),
		NumFDs:      numFds,
		NetSent:     sent,
		NetRecv:     recv,
	}
	return state, nil
}

// FilterProcesses 使用标签式过滤器过滤进程
func FilterProcesses(includes *TaggedFilter, excludes *TaggedFilter) ([]*ProcessInfo, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("processes: %w", err)
	}

	match := func(info *ProcessInfo) bool {
		// 首先检查exclude条件，如果匹配则排除
		if excludes != nil && excludes.Match(info) {
			return false
		}

		// 如果没有include条件，或者include条件匹配，则包含
		if includes == nil || includes.Match(info) {
			return true
		}

		return false
	}

	infos := make([]*ProcessInfo, 0)
	for _, p := range processes {
		if p.Pid == 1 {
			continue
		}
		status, _ := p.Status()
		if status == "" || status == "Z" {
			continue
		}

		info, err := GetProcessInfo(p)
		if err != nil {
			// 如果获取进程信息失败，跳过该进程（进程可能已经退出）
			continue
		}
		if match(info) {
			infos = append(infos, info)
		}
	}

	return infos, nil
}
