package procscan

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// TaggedFilterMatcher 标签式过滤器匹配器
type TaggedFilterMatcher interface {
	Match(info *ProcessInfo) bool
}

// TaggedFilter 标签式过滤器
type TaggedFilter struct {
	expression TaggedFilterMatcher
}

// Match 匹配进程信息
func (f *TaggedFilter) Match(info *ProcessInfo) bool {
	if f.expression == nil {
		return true
	}
	return f.expression.Match(info)
}

// FieldMatcher 字段匹配器
type FieldMatcher struct {
	field string // exe, cmd, cwd, ppid
	op    string // = 或 ~
	value string
	regex *regexp.Regexp
}

// Match 匹配进程信息
func (m *FieldMatcher) Match(info *ProcessInfo) bool {
	var fieldValue string
	switch m.field {
	case "exe":
		fieldValue = info.Exe
	case "cmd":
		fieldValue = info.Cmdline
	case "cwd":
		fieldValue = info.Cwd
	case "ppid":
		fieldValue = fmt.Sprintf("%d", info.PPID)
	default:
		return false
	}

	switch m.op {
	case "=":
		return fieldValue == m.value
	case "~":
		if m.regex == nil {
			return false
		}
		return m.regex.MatchString(fieldValue)
	default:
		return false
	}
}

// AndMatcher AND逻辑匹配器
type AndMatcher struct {
	left  TaggedFilterMatcher
	right TaggedFilterMatcher
}

// Match 匹配进程信息
func (m *AndMatcher) Match(info *ProcessInfo) bool {
	return m.left.Match(info) && m.right.Match(info)
}

// OrMatcher OR逻辑匹配器
type OrMatcher struct {
	left  TaggedFilterMatcher
	right TaggedFilterMatcher
}

// Match 匹配进程信息
func (m *OrMatcher) Match(info *ProcessInfo) bool {
	return m.left.Match(info) || m.right.Match(info)
}

// Token 解析token
type Token struct {
	Type  string // field, operator, value, logic
	Value string
}

// Tokenizer 词法分析器
type Tokenizer struct {
	input     string
	pos       int
	lastToken *Token // 记录上一个token，用于处理空值情况
}

// NewTokenizer 创建新的词法分析器
func NewTokenizer(input string) *Tokenizer {
	return &Tokenizer{
		input: strings.TrimSpace(input),
		pos:   0,
	}
}

// NextToken 获取下一个token
func (t *Tokenizer) NextToken() *Token {
	t.skipWhitespace()

	if t.pos >= len(t.input) {
		// 如果输入结束且上一个token是操作符，生成一个空值token
		if t.lastToken != nil && t.lastToken.Type == "operator" {
			emptyToken := &Token{Type: "value", Value: ""}
			t.lastToken = emptyToken // 更新lastToken防止重复生成
			return emptyToken
		}
		return nil
	}

	// 检查注释：遇到#时跳过该行剩余部分
	if t.input[t.pos] == '#' {
		t.skipComment()
		return t.NextToken() // 递归调用获取下一个有效token
	}

	// 检查逻辑操作符
	if t.pos+1 < len(t.input) {
		if t.input[t.pos:t.pos+2] == "&&" {
			// 如果上一个token是操作符，先生成空值token
			if t.lastToken != nil && t.lastToken.Type == "operator" {
				emptyToken := &Token{Type: "value", Value: ""}
				t.lastToken = emptyToken
				return emptyToken
			}
			t.pos += 2
			token := &Token{Type: "logic", Value: "&&"}
			t.lastToken = token
			return token
		}
		if t.input[t.pos:t.pos+2] == "||" {
			// 如果上一个token是操作符，先生成空值token
			if t.lastToken != nil && t.lastToken.Type == "operator" {
				emptyToken := &Token{Type: "value", Value: ""}
				t.lastToken = emptyToken
				return emptyToken
			}
			t.pos += 2
			token := &Token{Type: "logic", Value: "||"}
			t.lastToken = token
			return token
		}
	}

	// 检查操作符
	if t.input[t.pos] == '=' {
		t.pos++
		// 操作符后跳过空白，检查是否需要空值
		t.skipWhitespace()
		token := &Token{Type: "operator", Value: "="}
		t.lastToken = token
		return token
	}
	if t.input[t.pos] == '~' {
		t.pos++
		// 操作符后跳过空白，检查是否需要空值
		t.skipWhitespace()
		token := &Token{Type: "operator", Value: "~"}
		t.lastToken = token
		return token
	}

	// 检查引号字符串
	if t.input[t.pos] == '"' || t.input[t.pos] == '\'' {
		return t.readQuotedString()
	}

	// 读取标识符或值
	start := t.pos
	for t.pos < len(t.input) && !t.isDelimiter(t.input[t.pos]) {
		t.pos++
	}

	value := t.input[start:t.pos]
	var token *Token
	if value == "exe" || value == "cmd" || value == "cwd" || value == "ppid" {
		token = &Token{Type: "field", Value: value}
	} else {
		// 即使值为空也要返回值token，这样可以支持空字符串值
		// 但是只有在前面有操作符的情况下才这样做
		// 这里我们简单地总是返回值token，让解析器来处理
		token = &Token{Type: "value", Value: value}
	}

	t.lastToken = token
	return token
}

// skipWhitespace 跳过空白字符
func (t *Tokenizer) skipWhitespace() {
	for t.pos < len(t.input) && (t.input[t.pos] == ' ' || t.input[t.pos] == '\t') {
		t.pos++
	}
}

// skipComment 跳过注释（从#到行尾）
func (t *Tokenizer) skipComment() {
	for t.pos < len(t.input) && t.input[t.pos] != '\n' {
		t.pos++
	}
	// 跳过换行符
	if t.pos < len(t.input) && t.input[t.pos] == '\n' {
		t.pos++
	}
}

// isDelimiter 检查是否为分隔符
func (t *Tokenizer) isDelimiter(c byte) bool {
	return c == ' ' || c == '\t' || c == '=' || c == '~' || c == '&' || c == '|' || c == '#'
}

// readQuotedString 读取引号包围的字符串
func (t *Tokenizer) readQuotedString() *Token {
	quote := t.input[t.pos] // 记录开始的引号类型
	t.pos++                 // 跳过开始引号

	var value strings.Builder

	for t.pos < len(t.input) {
		char := t.input[t.pos]

		// 遇到结束引号
		if char == quote {
			t.pos++ // 跳过结束引号
			token := &Token{Type: "value", Value: value.String()}
			t.lastToken = token
			return token
		}

		// 处理转义字符
		if char == '\\' && t.pos+1 < len(t.input) {
			t.pos++ // 跳过反斜杠
			nextChar := t.input[t.pos]
			switch nextChar {
			case 'n':
				value.WriteByte('\n')
			case 't':
				value.WriteByte('\t')
			case 'r':
				value.WriteByte('\r')
			case '\\':
				value.WriteByte('\\')
			case '"':
				value.WriteByte('"')
			case '\'':
				value.WriteByte('\'')
			default:
				// 其他字符直接保留
				value.WriteByte('\\')
				value.WriteByte(nextChar)
			}
		} else {
			value.WriteByte(char)
		}

		t.pos++
	}

	// 如果到达文件结尾还没有找到结束引号，返回当前收集的值
	token := &Token{Type: "value", Value: value.String()}
	t.lastToken = token
	return token
}

// Parser 语法分析器
type Parser struct {
	tokenizer *Tokenizer
	current   *Token
}

// NewParser 创建新的语法分析器
func NewParser(input string) *Parser {
	tokenizer := NewTokenizer(input)
	parser := &Parser{
		tokenizer: tokenizer,
	}
	parser.advance()
	return parser
}

// advance 前进到下一个token
func (p *Parser) advance() {
	p.current = p.tokenizer.NextToken()
}

// ParseExpression 解析表达式
func (p *Parser) ParseExpression() (TaggedFilterMatcher, error) {
	return p.parseOrExpression()
}

// parseOrExpression 解析OR表达式
func (p *Parser) parseOrExpression() (TaggedFilterMatcher, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for p.current != nil && p.current.Type == "logic" && p.current.Value == "||" {
		p.advance() // 跳过 ||
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}
		left = &OrMatcher{left: left, right: right}
	}

	return left, nil
}

// parseAndExpression 解析AND表达式
func (p *Parser) parseAndExpression() (TaggedFilterMatcher, error) {
	left, err := p.parseFieldExpression()
	if err != nil {
		return nil, err
	}

	for p.current != nil && p.current.Type == "logic" && p.current.Value == "&&" {
		p.advance() // 跳过 &&
		right, err := p.parseFieldExpression()
		if err != nil {
			return nil, err
		}
		left = &AndMatcher{left: left, right: right}
	}

	return left, nil
}

// parseFieldExpression 解析字段表达式
func (p *Parser) parseFieldExpression() (TaggedFilterMatcher, error) {
	if p.current == nil || p.current.Type != "field" {
		return nil, fmt.Errorf("expected field name, got %v", p.current)
	}

	field := p.current.Value
	p.advance()

	if p.current == nil || p.current.Type != "operator" {
		return nil, fmt.Errorf("expected operator (= or ~), got %v", p.current)
	}

	op := p.current.Value
	p.advance()

	// 支持空字符串值：如果没有值token或值为空，则使用空字符串
	var value string
	if p.current != nil && p.current.Type == "value" {
		value = p.current.Value
		p.advance()
	} else {
		// 没有值token，使用空字符串
		value = ""
	}

	matcher := &FieldMatcher{
		field: field,
		op:    op,
		value: value,
	}

	// 如果是正则匹配，预编译正则表达式
	if op == "~" {
		if value == "" {
			return nil, errors.New("expected regex pattern, got empty")
		}
		regex, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %s: %w", value, err)
		}
		matcher.regex = regex
	}

	return matcher, nil
}

// ParseTaggedFilter 解析标签式过滤规则
// 支持单行和多行输入：
// - 单行：直接解析为单个表达式
// - 多行：每行解析为OR分支，空行和注释行会被忽略
func ParseTaggedFilter(rule string) (*TaggedFilter, error) {
	// 检查是否为多行输入
	if strings.Contains(rule, "\n") {
		return parseMultiLineRules(rule)
	}

	// 单行处理
	return parseSingleLineRule(rule)
}

// parseSingleLineRule 解析单行规则
func parseSingleLineRule(rule string) (*TaggedFilter, error) {
	// 移除首尾空白
	rule = strings.TrimSpace(rule)

	// 处理注释：移除#及其后面的内容
	if commentPos := strings.Index(rule, "#"); commentPos != -1 {
		rule = strings.TrimSpace(rule[:commentPos])
	}

	// 如果规则为空或者是纯注释，返回空过滤器
	if rule == "" {
		return &TaggedFilter{}, nil
	}

	parser := NewParser(rule)
	expression, err := parser.ParseExpression()
	if err != nil {
		return nil, fmt.Errorf("parseExpression '%s': %w", rule, err)
	}

	return &TaggedFilter{expression: expression}, nil
}

// parseMultiLineRules 解析多行规则，每行作为OR分支
func parseMultiLineRules(rules string) (*TaggedFilter, error) {
	lines := strings.Split(rules, "\n")
	var validExpressions []TaggedFilterMatcher

	for i, line := range lines {
		// 移除行首尾空白
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 处理行内注释：移除#及其后面的内容
		if commentPos := strings.Index(line, "#"); commentPos != -1 {
			line = strings.TrimSpace(line[:commentPos])
			if line == "" {
				continue
			}
		}

		// 解析单行规则
		filter, err := parseSingleLineRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}

		// 如果解析结果有有效表达式，添加到列表中
		if filter.expression != nil {
			validExpressions = append(validExpressions, filter.expression)
		}
	}

	// 如果没有有效表达式，返回空过滤器
	if len(validExpressions) == 0 {
		return &TaggedFilter{}, nil
	}

	// 如果只有一个表达式，直接返回
	if len(validExpressions) == 1 {
		return &TaggedFilter{expression: validExpressions[0]}, nil
	}

	// 多个表达式用OR连接
	result := validExpressions[0]
	for i := 1; i < len(validExpressions); i++ {
		result = &OrMatcher{left: result, right: validExpressions[i]}
	}

	return &TaggedFilter{expression: result}, nil
}
