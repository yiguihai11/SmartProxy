package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
)

// Color codes for console output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorGreen  = "\033[32m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[37m"
	ColorWhite  = "\033[97m"
)

// ColorHandler 自定义带颜色的处理器
type ColorHandler struct {
	slog.Handler
	w io.Writer
}

func NewColorHandler(w io.Writer, opts *slog.HandlerOptions) *ColorHandler {
	return &ColorHandler{
		Handler: slog.NewTextHandler(w, opts),
		w:       w,
	}
}

func (h *ColorHandler) Handle(ctx context.Context, r slog.Record) error {
	// 获取级别并着色
	level := r.Level.String()
	var coloredLevel string
	switch level {
	case "DEBUG":
		coloredLevel = fmt.Sprintf("%s%-7s%s", ColorPurple, level, ColorReset)
	case "INFO":
		coloredLevel = fmt.Sprintf("%s%-7s%s", ColorGreen, level, ColorReset)
	case "WARN":
		coloredLevel = fmt.Sprintf("%s%-7s%s", ColorYellow, level, ColorReset)
	case "ERROR":
		coloredLevel = fmt.Sprintf("%s%-7s%s", ColorRed, level, ColorReset)
	default:
		coloredLevel = fmt.Sprintf("%-7s", level)
	}

	// 获取时间
	t := r.Time.Format("2006-01-02 15:04:05")

	// 获取源码信息 - 优先使用自定义caller信息
	var source string
	callerInfo := ""

	// 先检查属性中是否有caller信息
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "caller" {
			callerInfo = a.Value.String()
		}
		return true
	})

	// 使用caller信息或从PC获取
	if callerInfo != "" {
		source = fmt.Sprintf("%s[%s]%s", ColorGray, callerInfo, ColorReset)
	} else {
		// 检查PC是否指向logger包
		fs := runtime.CallersFrames([]uintptr{r.PC})
		frame, _ := fs.Next()
		if frame.File != "" && strings.Contains(frame.File, "logger/") {
			// 如果PC指向logger包，不显示源码信息
			source = ""
		} else {
			// 否则显示PC指向的位置
			if fs := sourceFromPC(r.PC); fs != "" {
				source = fmt.Sprintf("%s[%s]%s", ColorGray, fs, ColorReset)
			}
		}
	}

	// 构建日志消息
	var b strings.Builder

	// 带颜色的时间和级别
	fmt.Fprintf(&b, "%s%s %s ", ColorCyan, t, coloredLevel)

	// 消息内容
	b.WriteString(r.Message)

	// 添加属性（跳过内部使用的caller属性）
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "caller" {
			// 跳过caller属性，这是内部使用的
			return true
		}
		if a.Key == "session_id" {
			// session_id 特殊格式
			fmt.Fprintf(&b, " %s[%s]%s", ColorBlue, a.Value.String(), ColorReset)
		} else if a.Key == "prefix" {
			// prefix 特殊格式
			fmt.Fprintf(&b, " %s", a.Value.String())
		} else {
			// 其他属性
			fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		}
		return true
	})

	// 添加源码信息
	if source != "" {
		fmt.Fprintf(&b, " %s", source)
	}

	fmt.Fprintln(h.w, b.String())
	return nil
}

// sourceFromPC 从 PC 获取源码信息
func sourceFromPC(pc uintptr) string {
	fs := runtime.CallersFrames([]uintptr{pc})
	frame, _ := fs.Next()
	if frame.File != "" {
		// 只显示文件名，不显示完整路径
		if idx := strings.LastIndex(frame.File, "/"); idx >= 0 {
			frame.File = frame.File[idx+1:]
		}
		return fmt.Sprintf("%s:%d", frame.File, frame.Line)
	}
	return ""
}

func (h *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ColorHandler{
		Handler: h.Handler.WithAttrs(attrs),
		w:       h.w,
	}
}

func (h *ColorHandler) WithGroup(name string) slog.Handler {
	return &ColorHandler{
		Handler: h.Handler.WithGroup(name),
		w:       h.w,
	}
}

// SlogLogger wraps slog.Logger for compatibility
type SlogLogger struct {
	logger *slog.Logger
	attrs  []slog.Attr
	mu     sync.RWMutex
}

// Config 日志配置
type Config struct {
	Level        string `json:"level"`        // debug, info, warn, error
	OutputFile   string `json:"output_file"`  // 日志文件路径，为空则输出到控制台
	EnableTime   bool   `json:"enable_time"`  // 是否显示时间戳
	Prefix       string `json:"prefix"`        // 日志前缀
	EnableColors bool   `json:"enable_colors"` // 是否启用颜色（仅控制台输出）
	MaxSize      int    `json:"max_size"`      // 日志文件最大大小(MB)
	MaxBackups   int    `json:"max_backups"`   // 保留的旧日志文件数量
	MaxAge       int    `json:"max_age"`       // 日志文件保存天数
	Compress     bool   `json:"compress"`      // 是否压缩旧日志文件
}

// defaultLogger 默认日志器
var defaultLogger *SlogLogger

func init() {
	// 初始化默认日志器
	defaultLogger = NewLogger()
	defaultLogger.SetLevel("info")
}

// NewLogger creates a new logger with slog
func NewLogger() *SlogLogger {
	// Use color handler by default for new loggers
	return NewLoggerWithOutput(os.Stdout, slog.LevelInfo)
}


// New 创建新的日志器（兼容原接口）
func New(config Config) (*SlogLogger, error) {
	var output io.Writer = os.Stdout

	// 解析日志级别
	var level slog.Level
	switch strings.ToLower(config.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// 如果指定了输出文件
	if config.OutputFile != "" {
		// 创建目录
		dir := strings.TrimSuffix(config.OutputFile, "/" + strings.TrimPrefix(config.OutputFile, "/"))
		if lastSlash := strings.LastIndex(dir, "/"); lastSlash > 0 {
			dir = dir[:lastSlash]
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create log directory: %v", err)
			}
		}

		// 打开文件
		file, err := os.OpenFile(config.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		output = file
	}

	// Create the logger with the appropriate handler
	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if isTerminal(output) && supportsColor() {
		// Terminal: Use color handler
		handler = NewColorHandler(output, &slog.HandlerOptions{
			Level:     opts.Level,
			AddSource: true,
		})
	} else {
		// File or non-terminal: Use our custom handler without colors
		handler = &ColorHandler{
			Handler: slog.NewTextHandler(output, &slog.HandlerOptions{
				Level:     opts.Level,
				AddSource: false, // 我们会手动处理源码信息
			}),
			w: output,
		}
	}

	slogLogger := &SlogLogger{
		logger: slog.New(handler),
		attrs:  make([]slog.Attr, 0),
	}

	// 添加前缀
	if config.Prefix != "" {
		slogLogger = slogLogger.WithField("prefix", config.Prefix)
	}

	return slogLogger, nil
}

// NewLoggerWithOutput creates a logger with specific output
func NewLoggerWithOutput(output io.Writer, level slog.Level) *SlogLogger {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if isTerminal(output) && supportsColor() {
		// Terminal: Always use our color handler
		handler = NewColorHandler(output, &slog.HandlerOptions{
			Level:     opts.Level,
			AddSource: true,
		})
	} else {
		// File or non-terminal: Use our custom handler without colors
		handler = &ColorHandler{
			Handler: slog.NewTextHandler(output, &slog.HandlerOptions{
				Level:     opts.Level,
				AddSource: false, // 我们会手动处理源码信息
			}),
			w: output,
		}
	}

	return &SlogLogger{
		logger: slog.New(handler),
		attrs:  make([]slog.Attr, 0),
	}
}




// isTerminal checks if the writer is a terminal
func isTerminal(w io.Writer) bool {
	// Check if it's os.Stdout or os.Stderr directly
	if w == os.Stdout || w == os.Stderr {
		// In Termux, check TERMUX_VERSION environment variable
		if os.Getenv("TERMUX_VERSION") != "" {
			return true
		}
		// For other systems, check if it's a character device
		if f, ok := w.(*os.File); ok {
			stat, err := f.Stat()
			if err != nil {
				return false
			}
			return (stat.Mode() & os.ModeCharDevice) != 0
		}
	}
	// For any other writer (like a file), return false
	return false
}

// supportsColor checks if the terminal supports colors
func supportsColor() bool {
	// Check environment variables
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check TERM environment variable
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return false
	}

	// Check for common terminal types that support color
	colorTerms := []string{
		"xterm", "xterm-256color", "screen", "tmux", "rxvt",
		"vt100", "ansi", "cygwin", "linux", "konsole",
	}

	for _, ct := range colorTerms {
		if strings.Contains(strings.ToLower(term), ct) {
			return true
		}
	}

	// Android Termux detection
	if os.Getenv("TERMUX_VERSION") != "" {
		return true
	}

	return false
}

// Format logging methods - compatible with existing interface
func (l *SlogLogger) Debug(format string, args ...interface{}) {
	if len(args) == 0 {
		l.log(slog.LevelDebug, format)
	} else {
		l.logf(slog.LevelDebug, format, args...)
	}
}

func (l *SlogLogger) Info(format string, args ...interface{}) {
	if len(args) == 0 {
		l.log(slog.LevelInfo, format)
	} else {
		l.logf(slog.LevelInfo, format, args...)
	}
}

func (l *SlogLogger) Warn(format string, args ...interface{}) {
	if len(args) == 0 {
		l.log(slog.LevelWarn, format)
	} else {
		l.logf(slog.LevelWarn, format, args...)
	}
}

func (l *SlogLogger) Error(format string, args ...interface{}) {
	if len(args) == 0 {
		l.log(slog.LevelError, format)
	} else {
		l.logf(slog.LevelError, format, args...)
	}
}

func (l *SlogLogger) Fatal(format string, args ...interface{}) {
	if len(args) == 0 {
		l.log(slog.LevelError, format)
	} else {
		l.logf(slog.LevelError, format, args...)
	}
	os.Exit(1)
}

// With fields support
func (l *SlogLogger) WithField(key string, value interface{}) *SlogLogger {
	l.mu.Lock()
	defer l.mu.Unlock()

	newLogger := &SlogLogger{
		logger: l.logger.With(key, value),
		attrs:  append(l.attrs, slog.Any(key, value)),
	}
	return newLogger
}

func (l *SlogLogger) WithFields(fields map[string]interface{}) *SlogLogger {
	l.mu.Lock()
	defer l.mu.Unlock()

	var args []any
	for k, v := range fields {
		args = append(args, k, v)
	}

	var attrs []slog.Attr
	for k, v := range fields {
		attrs = append(attrs, slog.Any(k, v))
	}

	newLogger := &SlogLogger{
		logger: l.logger.With(args...),
		attrs:  append(l.attrs, attrs...),
	}
	return newLogger
}

// SetLevel sets the log level
func (l *SlogLogger) SetLevel(level string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var slogLevel slog.Level
	switch strings.ToUpper(level) {
	case "DEBUG":
		slogLevel = slog.LevelDebug
	case "INFO":
		slogLevel = slog.LevelInfo
	case "WARN":
		slogLevel = slog.LevelWarn
	case "ERROR":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	// Create a new handler with the updated level
	// The handler type depends on the current output
	var handler slog.Handler
	if isTerminal(os.Stdout) && supportsColor() {
		// Terminal: Use color handler
		handler = NewColorHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slogLevel,
			AddSource: true,
		})
	} else {
		// File or non-terminal: Use JSON handler
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slogLevel,
		})
	}

	l.logger = slog.New(handler)
}

// Close 关闭日志器（兼容接口）
func (l *SlogLogger) Close() error {
	// slog不需要显式关闭
	return nil
}

// Helper methods
func (l *SlogLogger) log(level slog.Level, args ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if !l.logger.Enabled(context.Background(), level) {
		return
	}

	// 获取调用者信息
	pcs := make([]uintptr, 6)
	n := runtime.Callers(4, pcs)
	var callerInfo string

	if n > 0 {
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			if !more {
				break
			}
			// 如果不是logger包，使用这个调用信息
			if !strings.Contains(frame.File, "logger/") {
				// 只提取文件名
				filename := frame.File
				if idx := strings.LastIndex(filename, "/"); idx >= 0 {
					filename = filename[idx+1:]
				}
				callerInfo = fmt.Sprintf("%s:%d", filename, frame.Line)
				break
			}
		}
	}

	msg := fmt.Sprint(args...)
	if callerInfo != "" {
		l.logger.Log(context.Background(), level, msg, slog.String("caller", callerInfo))
	} else {
		l.logger.Log(context.Background(), level, msg)
	}
}

func (l *SlogLogger) logf(level slog.Level, format string, args ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if !l.logger.Enabled(context.Background(), level) {
		return
	}

	// 获取调用者信息
	pcs := make([]uintptr, 6)
	n := runtime.Callers(4, pcs)
	var callerInfo string

	if n > 0 {
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			if !more {
				break
			}
			// 如果不是logger包，使用这个调用信息
			if !strings.Contains(frame.File, "logger/") {
				// 只提取文件名
				filename := frame.File
				if idx := strings.LastIndex(filename, "/"); idx >= 0 {
					filename = filename[idx+1:]
				}
				callerInfo = fmt.Sprintf("%s:%d", filename, frame.Line)
				break
			}
		}
	}

	msg := fmt.Sprintf(format, args...)
	if callerInfo != "" {
		l.logger.Log(context.Background(), level, msg, slog.String("caller", callerInfo))
	} else {
		l.logger.Log(context.Background(), level, msg)
	}
}

// Global functions for backward compatibility
func SetLevel(level string) {
	defaultLogger.SetLevel(level)
}

func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

func Warn(format string, args ...interface{}) {
	defaultLogger.Warn(format, args...)
}

func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

func Fatal(format string, args ...interface{}) {
	defaultLogger.Fatal(format, args...)
}

// WithPrefix 创建带有前缀的日志器（兼容接口）
func WithPrefix(prefix string) *SlogLogger {
	return defaultLogger.WithField("prefix", prefix)
}

// WithField 创建带有一个字段的日志器
func WithField(key string, value interface{}) *SlogLogger {
	return defaultLogger.WithField(key, value)
}

// WithFields 创建带有多个字段的日志器
func WithFields(fields map[string]interface{}) *SlogLogger {
	return defaultLogger.WithFields(fields)
}

// GetCaller 获取调用者信息
func GetCaller() (string, string, int) {
	pc, file, line, ok := runtime.Caller(2)
	if !ok {
		return "", "unknown", 0
	}

	// 获取函数名
	fn := runtime.FuncForPC(pc)
	funcName := fn.Name()

	// 提取文件名
	if lastSlash := strings.LastIndex(file, "/"); lastSlash >= 0 {
		file = file[lastSlash+1:]
	}

	return funcName, file, line
}

// WithCaller 添加调用者信息
func (l *SlogLogger) WithCaller() *SlogLogger {
	funcName, filename, line := GetCaller()

	fields := map[string]interface{}{
		"func": funcName,
		"file": filename,
		"line": line,
	}

	return l.WithFields(fields)
}

// 全局WithCaller
func WithCaller() *SlogLogger {
	return defaultLogger.WithCaller()
}

