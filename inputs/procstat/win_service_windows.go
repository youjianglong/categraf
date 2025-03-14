//go:build windows
// +build windows

package procstat

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func getService(name string) (*mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()

	srv, err := m.OpenService(name)
	if err != nil {
		return nil, err
	}

	return srv, nil
}

func queryPidWithWinServiceName(winServiceName string) (uint32, error) {
	srv, err := getService(winServiceName)
	if err != nil {
		return 0, err
	}
	defer func(srv *mgr.Service) {
		err := srv.Close()
		if err != nil {
			log.Printf("E! Close srv error: %s", err)
		}
	}(srv)

	var p *windows.SERVICE_STATUS_PROCESS
	var bytesNeeded uint32
	var buf []byte

	if err := windows.QueryServiceStatusEx(srv.Handle, windows.SC_STATUS_PROCESS_INFO, nil, 0, &bytesNeeded); err != windows.ERROR_INSUFFICIENT_BUFFER {
		return 0, err
	}

	buf = make([]byte, bytesNeeded)
	p = (*windows.SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceStatusEx(srv.Handle, windows.SC_STATUS_PROCESS_INFO, &buf[0], uint32(len(buf)), &bytesNeeded); err != nil {
		return 0, err
	}
	if p.CurrentState != windows.SERVICE_RUNNING {
		return 0, fmt.Errorf("winServiceName %s is not running, currentState:%d", winServiceName, p.CurrentState)
	}

	return p.ProcessId, nil
}
