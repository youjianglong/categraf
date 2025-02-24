package tzservice

import (
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

func sub(sep string, idx int, src string) string {
	sp := strings.Split(src, sep)
	return sp[idx]
}

func subn(sep string, idx int, n int, src string) string {
	sp := strings.SplitN(src, sep, n)
	return sp[idx]
}

func match(pattern string, src string) bool {
	p, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return p.MatchString(src)
}

func findString(pattern string, src string) string {
	p, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	return p.FindString(src)
}

func findSubString(pattern string, n int, src string) string {
	p, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	ss := p.FindStringSubmatch(src)
	if len(ss) <= n {
		return ""
	}
	return ss[n]
}

func replace(old, new string, n int, src string) string {
	return strings.Replace(src, old, new, n)
}

func replaceAll(old, new string, src string) string {
	return strings.ReplaceAll(src, old, new)
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func atoi64(s string) int64 {
	i, _ := strconv.ParseInt(s, 10, 64)
	return i
}

func atof64(s string) float64 {
	i, _ := strconv.ParseFloat(s, 64)
	return i
}

func split(sep string, src string) []string {
	return strings.Split(src, sep)
}

func pathGet(key string, src any) any {
	return PathGet(src, key)
}

var tplFuncMap = template.FuncMap{
	"sub":           sub,
	"subn":          subn,
	"split":         split,
	"match":         match,
	"findString":    findString,
	"findSubString": findSubString,
	"replace":       replace,
	"replaceAll":    replaceAll,
	"trim":          strings.TrimSpace,
	"atoi":          atoi,
	"atoi64":        atoi64,
	"atof64":        atof64,
	"pathGet":       pathGet,
}
