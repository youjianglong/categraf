package procscan

import (
	"testing"
)

func TestParseTaggedFilter(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		wantErr bool
	}{
		{
			name:    "空规则",
			rule:    "",
			wantErr: false,
		},
		{
			name:    "简单精确匹配",
			rule:    "exe=ps",
			wantErr: false,
		},
		{
			name:    "简单正则匹配",
			rule:    "cmd~java.+Data.+",
			wantErr: false,
		},
		{
			name:    "AND组合",
			rule:    "exe=ps && cwd=/root",
			wantErr: false,
		},
		{
			name:    "OR组合",
			rule:    "cmd~java.+Data.+ || cwd=/home/data",
			wantErr: false,
		},
		{
			name:    "复杂组合",
			rule:    "exe=nginx && cmd~master.+ || cwd=/var/log",
			wantErr: false,
		},
		{
			name:    "无效的字段名",
			rule:    "invalid=test",
			wantErr: true,
		},
		{
			name:    "无效的操作符",
			rule:    "exe@test",
			wantErr: true,
		},
		{
			name:    "无效的正则表达式",
			rule:    "cmd~[",
			wantErr: true,
		},
		{
			name:    "空字符串值 - 精确匹配",
			rule:    "exe=",
			wantErr: false,
		},
		{
			name:    "空字符串值 - 正则匹配",
			rule:    "cmd~",
			wantErr: true, // 空正则表达式无效
		},
		{
			name:    "空字符串值在AND表达式中",
			rule:    "exe= && cwd=/root",
			wantErr: false,
		},
		{
			name:    "行内注释",
			rule:    "exe=ps # 这是注释",
			wantErr: false,
		},
		{
			name:    "纯注释行应该被忽略",
			rule:    "# 这是一个注释",
			wantErr: false, // 应该返回空过滤器
		},
		{
			name:    "多行规则 - 简单OR",
			rule:    "exe=nginx\nexe=apache2",
			wantErr: false,
		},
		{
			name:    "多行规则 - 包含注释",
			rule:    "exe=nginx # web服务器\ncmd~java.+ # Java应用",
			wantErr: false,
		},
		{
			name:    "多行规则 - 空行和注释",
			rule:    "# 注释\n\nexe=nginx\n# 另一个注释\ncwd=/root",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := ParseTaggedFilter(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTaggedFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && filter == nil {
				t.Errorf("ParseTaggedFilter() returned nil filter without error")
			}
		})
	}
}

func TestTaggedFilterMatch(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		process  *ProcessInfo
		expected bool
	}{
		{
			name: "exe精确匹配成功",
			rule: "exe=ps",
			process: &ProcessInfo{
				Exe:     "ps",
				Cmdline: "ps aux",
				Cwd:     "/root",
			},
			expected: true,
		},
		{
			name: "exe精确匹配失败",
			rule: "exe=ps",
			process: &ProcessInfo{
				Exe:     "top",
				Cmdline: "top",
				Cwd:     "/root",
			},
			expected: false,
		},
		{
			name: "cmd正则匹配成功",
			rule: "cmd~java.+Data.+",
			process: &ProcessInfo{
				Exe:     "java",
				Cmdline: "java -jar MyDataProcessor.jar",
				Cwd:     "/home/app",
			},
			expected: true,
		},
		{
			name: "cmd正则匹配失败",
			rule: "cmd~java.+Data.+",
			process: &ProcessInfo{
				Exe:     "java",
				Cmdline: "java -jar MyWebApp.jar",
				Cwd:     "/home/app",
			},
			expected: false,
		},
		{
			name: "cwd精确匹配成功",
			rule: "cwd=/root",
			process: &ProcessInfo{
				Exe:     "bash",
				Cmdline: "bash",
				Cwd:     "/root",
			},
			expected: true,
		},
		{
			name: "AND组合匹配成功",
			rule: "exe=ps && cwd=/root",
			process: &ProcessInfo{
				Exe:     "ps",
				Cmdline: "ps aux",
				Cwd:     "/root",
			},
			expected: true,
		},
		{
			name: "AND组合匹配失败（第一个条件不满足）",
			rule: "exe=ps && cwd=/root",
			process: &ProcessInfo{
				Exe:     "top",
				Cmdline: "top",
				Cwd:     "/root",
			},
			expected: false,
		},
		{
			name: "AND组合匹配失败（第二个条件不满足）",
			rule: "exe=ps && cwd=/root",
			process: &ProcessInfo{
				Exe:     "ps",
				Cmdline: "ps aux",
				Cwd:     "/home",
			},
			expected: false,
		},
		{
			name: "OR组合匹配成功（第一个条件满足）",
			rule: "cmd~java.+Data.+ || cwd=/home/data",
			process: &ProcessInfo{
				Exe:     "java",
				Cmdline: "java -jar MyDataProcessor.jar",
				Cwd:     "/home/app",
			},
			expected: true,
		},
		{
			name: "OR组合匹配成功（第二个条件满足）",
			rule: "cmd~java.+Data.+ || cwd=/home/data",
			process: &ProcessInfo{
				Exe:     "python",
				Cmdline: "python app.py",
				Cwd:     "/home/data",
			},
			expected: true,
		},
		{
			name: "OR组合匹配失败（两个条件都不满足）",
			rule: "cmd~java.+Data.+ || cwd=/home/data",
			process: &ProcessInfo{
				Exe:     "python",
				Cmdline: "python web.py",
				Cwd:     "/home/web",
			},
			expected: false,
		},
		{
			name: "复杂组合匹配",
			rule: "exe=nginx && cmd~master.+ || cwd=/var/log",
			process: &ProcessInfo{
				Exe:     "nginx",
				Cmdline: "nginx: master process",
				Cwd:     "/etc/nginx",
			},
			expected: true,
		},
		{
			name: "空规则匹配（应该总是返回true）",
			rule: "",
			process: &ProcessInfo{
				Exe:     "any",
				Cmdline: "any command",
				Cwd:     "/any/path",
			},
			expected: true,
		},
		{
			name: "exe空字符串值匹配成功",
			rule: "exe=",
			process: &ProcessInfo{
				Exe:     "",
				Cmdline: "some command",
				Cwd:     "/root",
			},
			expected: true,
		},
		{
			name: "exe空字符串值匹配失败",
			rule: "exe=",
			process: &ProcessInfo{
				Exe:     "ps",
				Cmdline: "ps aux",
				Cwd:     "/root",
			},
			expected: false,
		},
		{
			name: "cmd空字符串值匹配成功",
			rule: "cmd=",
			process: &ProcessInfo{
				Exe:     "test",
				Cmdline: "",
				Cwd:     "/root",
			},
			expected: true,
		},
		{
			name: "cwd空字符串值匹配成功",
			rule: "cwd=",
			process: &ProcessInfo{
				Exe:     "test",
				Cmdline: "test cmd",
				Cwd:     "",
			},
			expected: true,
		},
		{
			name: "AND组合包含空字符串值",
			rule: "exe= && cwd=/root",
			process: &ProcessInfo{
				Exe:     "",
				Cmdline: "some command",
				Cwd:     "/root",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := ParseTaggedFilter(tt.rule)
			if err != nil {
				t.Fatalf("ParseTaggedFilter() error = %v", err)
			}

			result := filter.Match(tt.process)
			if result != tt.expected {
				t.Errorf("TaggedFilter.Match() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestTokenizer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []Token
	}{
		{
			name:  "简单字段表达式",
			input: "exe=ps",
			expected: []Token{
				{Type: "field", Value: "exe"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "ps"},
			},
		},
		{
			name:  "正则表达式",
			input: "cmd~java.+",
			expected: []Token{
				{Type: "field", Value: "cmd"},
				{Type: "operator", Value: "~"},
				{Type: "value", Value: "java.+"},
			},
		},
		{
			name:  "AND表达式",
			input: "exe=ps && cwd=/root",
			expected: []Token{
				{Type: "field", Value: "exe"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "ps"},
				{Type: "logic", Value: "&&"},
				{Type: "field", Value: "cwd"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "/root"},
			},
		},
		{
			name:  "OR表达式",
			input: "cmd~java || cwd=/home",
			expected: []Token{
				{Type: "field", Value: "cmd"},
				{Type: "operator", Value: "~"},
				{Type: "value", Value: "java"},
				{Type: "logic", Value: "||"},
				{Type: "field", Value: "cwd"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "/home"},
			},
		},
		{
			name:  "空字符串值",
			input: "exe=",
			expected: []Token{
				{Type: "field", Value: "exe"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: ""},
			},
		},
		{
			name:  "空字符串值在AND表达式中",
			input: "exe= && cwd=/root",
			expected: []Token{
				{Type: "field", Value: "exe"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: ""},
				{Type: "logic", Value: "&&"},
				{Type: "field", Value: "cwd"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "/root"},
			},
		},
		{
			name:  "行内注释",
			input: "exe=ps # 这是注释",
			expected: []Token{
				{Type: "field", Value: "exe"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "ps"},
			},
		},
		{
			name:     "纯注释",
			input:    "# 这是一个注释",
			expected: []Token{}, // 应该没有token
		},
		{
			name:  "注释前有空格",
			input: "exe=nginx   # nginx进程",
			expected: []Token{
				{Type: "field", Value: "exe"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "nginx"},
			},
		},
		{
			name:  "双引号字符串",
			input: `exe="/usr/bin/my app"`,
			expected: []Token{
				{Type: "field", Value: "exe"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "/usr/bin/my app"},
			},
		},
		{
			name:  "单引号字符串",
			input: "exe='/usr/bin/my app'",
			expected: []Token{
				{Type: "field", Value: "exe"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "/usr/bin/my app"},
			},
		},
		{
			name:  "引号内包含特殊字符",
			input: `cmd="java -jar app.jar && echo done"`,
			expected: []Token{
				{Type: "field", Value: "cmd"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: "java -jar app.jar && echo done"},
			},
		},
		{
			name:  "引号内包含转义字符",
			input: `cmd="echo \"hello world\""`,
			expected: []Token{
				{Type: "field", Value: "cmd"},
				{Type: "operator", Value: "="},
				{Type: "value", Value: `echo "hello world"`},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := NewTokenizer(tt.input)
			var tokens []Token

			for {
				token := tokenizer.NextToken()
				if token == nil {
					break
				}
				tokens = append(tokens, *token)
			}

			if len(tokens) != len(tt.expected) {
				t.Errorf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
				return
			}

			for i, expected := range tt.expected {
				if tokens[i].Type != expected.Type || tokens[i].Value != expected.Value {
					t.Errorf("Token %d: expected {%s, %s}, got {%s, %s}",
						i, expected.Type, expected.Value, tokens[i].Type, tokens[i].Value)
				}
			}
		})
	}
}

// TestParseTaggedFilterMultiLine 测试多行规则解析，包括注释支持
func TestParseTaggedFilterMultiLine(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		wantErr bool
		// 验证函数，用于检查解析结果是否正确
		verify func(*TaggedFilter) bool
	}{
		{
			name: "包含注释的多行规则",
			rules: `# 这是注释行
exe=nginx          # nginx进程
cmd~java.+Data.+  # Java数据处理进程
# 另一个注释
cwd=/root`,
			wantErr: false,
			verify: func(filter *TaggedFilter) bool {
				// 应该是OR组合的三个条件
				return filter.expression != nil
			},
		},
		{
			name: "纯注释和空行",
			rules: `# 第一个注释

# 第二个注释
   # 带空格的注释

`,
			wantErr: false,
			verify: func(filter *TaggedFilter) bool {
				// 应该是空过滤器
				return filter.expression == nil
			},
		},
		{
			name: "混合规则和注释",
			rules: `exe=ps # ps进程
# 跳过这行
cmd= # 空命令行
cwd~.+ # 非空工作目录`,
			wantErr: false,
			verify: func(filter *TaggedFilter) bool {
				// 应该有有效的表达式
				return filter.expression != nil
			},
		},
		{
			name: "行内注释中的特殊字符",
			rules: `exe=nginx # 包含 && || = ~ 等特殊字符的注释
cmd~test.*`,
			wantErr: false,
			verify: func(filter *TaggedFilter) bool {
				// 应该是OR组合的两个条件
				return filter.expression != nil
			},
		},
		{
			name:    "单行规则（兼容性测试）",
			rules:   `exe=nginx`,
			wantErr: false,
			verify: func(filter *TaggedFilter) bool {
				// 应该有有效的表达式
				return filter.expression != nil
			},
		},
		{
			name: "多行OR逻辑验证",
			rules: `exe=nginx
exe=apache2`,
			wantErr: false,
			verify: func(filter *TaggedFilter) bool {
				// 测试OR逻辑：nginx进程应该匹配
				nginxProcess := &ProcessInfo{Exe: "nginx", Cmdline: "nginx master", Cwd: "/etc/nginx"}
				apacheProcess := &ProcessInfo{Exe: "apache2", Cmdline: "apache2", Cwd: "/etc/apache2"}
				otherProcess := &ProcessInfo{Exe: "other", Cmdline: "other", Cwd: "/tmp"}

				return filter.Match(nginxProcess) && filter.Match(apacheProcess) && !filter.Match(otherProcess)
			},
		},
		{
			name: "详细多行OR逻辑测试",
			rules: `exe=nginx # web服务器
cmd~java.*myapp # Java应用
cwd=/home/user # 用户目录进程`,
			wantErr: false,
			verify: func(filter *TaggedFilter) bool {
				// 三种不同类型的进程都应该匹配
				nginxProcess := &ProcessInfo{Exe: "nginx", Cmdline: "nginx worker", Cwd: "/etc/nginx"}
				javaProcess := &ProcessInfo{Exe: "java", Cmdline: "java -jar myapp.jar", Cwd: "/opt/java"}
				userProcess := &ProcessInfo{Exe: "bash", Cmdline: "bash", Cwd: "/home/user"}
				otherProcess := &ProcessInfo{Exe: "other", Cmdline: "other", Cwd: "/tmp"}

				// 单独测试每个匹配
				nginx := filter.Match(nginxProcess)
				java := filter.Match(javaProcess)
				user := filter.Match(userProcess)
				other := filter.Match(otherProcess)

				// 如果有任何匹配失败，打印调试信息
				if !nginx || !java || !user || other {
					t.Logf("Match results: nginx=%v, java=%v, user=%v, other=%v", nginx, java, user, other)
					t.Logf("Java cmdline: '%s'", javaProcess.Cmdline)
				}

				return nginx && java && user && !other
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := ParseTaggedFilter(tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTaggedFilter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && filter == nil {
				t.Errorf("ParseTaggedFilter() returned nil filter without error")
				return
			}

			if !tt.wantErr && tt.verify != nil && !tt.verify(filter) {
				t.Errorf("ParseTaggedFilter() verification failed")
			}
		})
	}
}

// 测试引号字符串的完整过滤功能
func TestQuotedStringFiltering(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		process  *ProcessInfo
		expected bool
	}{
		{
			name: "包含空格的exe路径匹配",
			rule: `exe="/usr/bin/my app"`,
			process: &ProcessInfo{
				Exe:     "/usr/bin/my app",
				Cmdline: "my app --config file.conf",
				Cwd:     "/home/user",
			},
			expected: true,
		},
		{
			name: "包含特殊字符的命令行匹配",
			rule: `cmd="java -jar app.jar && echo done"`,
			process: &ProcessInfo{
				Exe:     "/usr/bin/java",
				Cmdline: "java -jar app.jar && echo done",
				Cwd:     "/opt/app",
			},
			expected: true,
		},
		{
			name: "包含&字符的工作目录匹配",
			rule: `cwd="/home/user/my&project"`,
			process: &ProcessInfo{
				Exe:     "/usr/bin/node",
				Cmdline: "node server.js",
				Cwd:     "/home/user/my&project",
			},
			expected: true,
		},
		{
			name: "引号内正则表达式匹配",
			rule: `cmd~"java.*jar.*echo"`,
			process: &ProcessInfo{
				Exe:     "/usr/bin/java",
				Cmdline: "java -jar app.jar && echo done",
				Cwd:     "/opt/app",
			},
			expected: true,
		},
		{
			name: "引号字符串组合条件",
			rule: `exe="/usr/bin/my app" && cwd="/home/user/my&project"`,
			process: &ProcessInfo{
				Exe:     "/usr/bin/my app",
				Cmdline: "my app --verbose",
				Cwd:     "/home/user/my&project",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := ParseTaggedFilter(tt.rule)
			if err != nil {
				t.Fatalf("ParseTaggedFilter() error = %v", err)
			}

			result := filter.Match(tt.process)
			if result != tt.expected {
				t.Errorf("Filter.Match() = %v, expected %v", result, tt.expected)
				t.Logf("Rule: %s", tt.rule)
				t.Logf("Process: exe='%s', cmd='%s', cwd='%s'",
					tt.process.Exe, tt.process.Cmdline, tt.process.Cwd)
			}
		})
	}
}
