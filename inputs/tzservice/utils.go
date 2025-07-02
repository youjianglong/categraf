package tzservice

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"
)

type H = map[string]interface{}
type S = map[string]string

func PathGet(val interface{}, key string) interface{} {
	if key == "" {
		return val
	}
	var dict H
	var slice []interface{}
	switch v := val.(type) {
	case []interface{}:
		slice = v
	case H:
		dict = v
	default:
		r := reflect.ValueOf(val)
		if r.Kind() == reflect.Ptr {
			r = r.Elem()
		}
		if r.Kind() == reflect.Slice {
			size := r.Len()
			for i := 0; i < size; i++ {
				slice = append(slice, r.Index(i).Interface())
			}
		}
	}
	nodes := strings.Split(key, ".")
	end := len(nodes) - 1
	for i, n := range nodes {
		if n == "*" {
			if i == end {
				break
			}
			if slice == nil {
				continue
			}
			k := strings.Join(nodes[i+1:], ".")
			var rows []interface{}
			for _, v := range slice {
				v = PathGet(v, k)
				if v == nil {
					continue
				}
				vs, ok := v.([]interface{})
				if ok {
					rows = append(rows, vs...)
				} else {
					rows = append(rows, v)
				}
			}
			return rows
		}
		var v interface{}
		if dict != nil {
			var ok bool
			v, ok = dict[n]
			if !ok {
				return nil
			}
		} else if slice != nil {
			idx, err := strconv.Atoi(n)
			if err != nil {
				log.Println(err)
				return nil
			}
			if idx < 0 || len(slice) <= idx {
				return nil
			}
			v = slice[idx]
		}
		if v == nil {
			return nil
		}
		switch tv := v.(type) {
		case H:
			dict = tv
			slice = nil
			continue
		case []interface{}:
			dict = nil
			slice = tv
			continue
		default:
			if end == i {
				return v
			}
			return nil
		}
	}
	if dict != nil {
		return dict
	}
	return slice
}

func ParseCmd(cmd string, shell bool) (name string, args []string) {
	if shell {
		if runtime.GOOS == "windows" {
			name = "cmd"
			args = append(args, "/C")
		} else {
			name = "sh"
			args = append(args, "-c")
		}
		args = append(args, cmd)
		return
	}
	var escape bool
	var quote rune
	var rs []rune

	for _, r := range cmd {
		if escape {
			switch r {
			case 'r':
				rs = append(rs, '\r')
			case 'n':
				rs = append(rs, '\n')
			case 't':
				rs = append(rs, '\t')
			case '\\':
				rs = append(rs, '\\')
			default:
				rs = append(rs, r)
			}
			escape = false
			continue
		}
		switch r {
		case '"', '\'':
			if quote == r {
				quote = 0
			} else if quote > 0 {
				rs = append(rs, r)
			} else {
				quote = r
			}
		case '\\':
			escape = true
		case ' ':
			if quote > 0 {
				rs = append(rs, r)
			} else {
				if len(rs) > 0 {
					args = append(args, string(rs))
					rs = nil
				}
			}
		default:
			rs = append(rs, r)
		}
	}
	if len(rs) > 0 {
		args = append(args, string(rs))
	}
	name = args[0]
	args = args[1:]
	return
}

func GetLocalIP() string {
	server := "119.29.29.29:53"
	conn, err := net.DialTimeout("udp", server, time.Second)
	if err != nil {
		log.Println(err)
		return ""
	}
	defer conn.Close()
	return strings.SplitN(conn.LocalAddr().String(), ":", 2)[0]
}

func Md5Str(s string) string {
	b := md5.Sum([]byte(s))
	return hex.EncodeToString(b[:])
}

type ProcessState struct {
	Pid         int32
	MemoryInfo  *process.MemoryInfoStat
	CpuPercent  float64
	ElapsedTime float64
}

func GetProcessState(logger *logrus.Entry, p *process.Process) *ProcessState {
	memInfo, err := p.MemoryInfo()
	if err != nil {
		logger.WithError(err).Error("获取内存信息失败")
		return nil
	}
	cpuPercent, err := p.Percent(0)
	if err != nil {
		logger.WithError(err).Error("获取cpu使用率失败")
		return nil
	}
	createTime, err := p.CreateTime()
	if err != nil {
		logger.WithError(err).Error("获取创建时间失败")
	}
	return &ProcessState{
		Pid:         p.Pid,
		MemoryInfo:  memInfo,
		CpuPercent:  cpuPercent,
		ElapsedTime: float64(time.Now().Unix() - (createTime / 1000)),
	}
}

func GetStacks(skip int) []string {
	stacks := make([]string, 0)
	for {
		skip++
		_, file, line, ok := runtime.Caller(skip)
		if !ok {
			break
		}
		stacks = append(stacks, fmt.Sprintf("%s:%d", file, line))
	}
	return stacks
}
