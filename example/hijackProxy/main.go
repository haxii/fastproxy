package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/log"
)

var (
	defaultLogger = &log.DefaultLogger{}
	defaultConfig *config
	fileDir       = "files"
)

func main() {
	proxy := proxy.Proxy{
		Logger: defaultLogger,
		Handler: proxy.Handler{
			ShouldAllowConnection: func(conn net.Addr) bool {
				fmt.Printf("allowed connection from %s\n", conn.String())
				return true
			},
			ShouldDecryptHost: func(userdata *proxy.UserData, host string) bool {
				return !isInForwardList(host)
			},
			RewriteURL: func(userdata *proxy.UserData, hostWithPort string) string {
				return hostWithPort
			},
			HijackerPool: &SimpleHijackerPool{},
		},
		ServerIdleDuration: time.Second * 30,
	}

	defaultLogger.Info("app", "listening on：7890")
	panic(proxy.Serve("tcp", "0.0.0.0:7890"))
}

//SimpleHijackerPool implements the HijackerPool based on simpleHijacker & sync.Pool
type SimpleHijackerPool struct {
	pool sync.Pool
}

//Get get a simple hijacker from pool
func (p *SimpleHijackerPool) Get(clientAddr net.Addr,
	targetHost string, method, path []byte, userdata *proxy.UserData) proxy.Hijacker {
	v := p.pool.Get()
	var h *simpleHijacker
	if v == nil {
		h = &simpleHijacker{}
	} else {
		h = v.(*simpleHijacker)
	}
	h.Set(clientAddr, targetHost, method, path, userdata)
	return h
}

//Put puts a simple hijacker back to pool
func (p *SimpleHijackerPool) Put(s proxy.Hijacker) {
	hijacker := s.(*simpleHijacker)
	hijacker.Release()
	p.pool.Put(s)
}

type simpleHijacker struct {
	clientAddr, targetHost string
	method, path           []byte
	userdata               *proxy.UserData
	file                   *os.File
}

func (s *simpleHijacker) Set(clientAddr net.Addr,
	host string, method, path []byte, userdata *proxy.UserData) {
	s.clientAddr = clientAddr.String()
	s.targetHost = host
	s.method = method
	s.path = path
	s.userdata = userdata
}

func (s *simpleHijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (s *simpleHijacker) HijackResponse() io.Reader {
	return nil
}

func (s *simpleHijacker) Release() {
	if s.file != nil {
		s.file.Close()
	}
}

func (s *simpleHijacker) OnResponse(respLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	defaultLogger.Info("app", path.Join(s.targetHost, string(s.path)))

	host, _, err := net.SplitHostPort(s.targetHost)
	if err != nil {
		defaultLogger.Error("app", err, "split host port error")
		host = s.targetHost
	}

	if len(defaultConfig.SpecialHost) > 0 && defaultConfig.SpecialHost != host {
		return nil
	}

	urlpath := string(s.path)
	if len(urlpath) <= 1 {
		return nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		defaultLogger.Error("app", err, "getwd error")
		return nil
	}

	mainDir := filepath.Join(cwd, fileDir, host)
	subDir, fileName := path.Split(urlpath)
	totalDir := filepath.Join(mainDir, subDir)
	fileInfo, err := os.Lstat(totalDir)
	if err != nil && !os.IsNotExist(err) {
		defaultLogger.Error("app", err, "Lstat error")
		return nil
	}
	if fileInfo == nil || !fileInfo.IsDir() {
		err := os.MkdirAll(totalDir, 0700)
		if err != nil {
			defaultLogger.Error("app", err, "MkdirAll error")
			return nil
		}
	}

	idx := strings.IndexByte(fileName, '?')
	if idx > -1 {
		fileName = string([]byte(fileName)[:idx])
	}
	filePath := filepath.Join(totalDir, fileName)
	file, err := os.Create(filePath)
	if err != nil {
		defaultLogger.Error("app", err, "create file error")
		return nil
	}
	s.file = file
	return s.file
}

type config struct {
	SpecialHost string   // save resource for special host
	ForwardList []string // no-decrypt host list
}

func loadConfig() {
	buf, err := ioutil.ReadFile("./config.json")
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(buf, &defaultConfig)
	if err != nil {
		panic(err)
	}
}

func isInForwardList(curHost string) bool {
	for _, host := range defaultConfig.ForwardList {
		if curHost == host {
			return true
		}
	}
	return false
}
