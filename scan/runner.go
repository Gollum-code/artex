package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Profile is one configured scanner: what to run, with which arguments, and how
// to read the result. It mirrors the scanner_profiles table.
type Profile struct {
	ID             int64
	Name           string
	Binary         string
	Args           []string
	Format         string
	TimeoutSeconds int
	Enabled        bool
	Builtin        bool
}

// DefaultTimeout is used when a profile does not set one.
const DefaultTimeout = 10 * time.Minute

// MaxOutput bounds how many bytes of stdout are retained. A rogue scanner must
// not be able to exhaust memory; the parser only needs the record stream.
const MaxOutput = 64 << 20

// RunSpec is one concrete invocation.
type RunSpec struct {
	Profile Profile
	Target  string
	// Vars fills non-target placeholders ({{wordlist}}, {{extensions}}, ...).
	Vars map[string]string
}

// RunOutput is the raw outcome plus the parsed result.
type RunOutput struct {
	Result     *Result
	ExitCode   int
	Stdout     []byte
	Stderr     string
	StartedAt  time.Time
	FinishedAt time.Time
	TimedOut   bool
	Truncated  bool
}

// BuildArgs expands a profile's argument template for one target. Placeholders
// are substituted literally (no shell), so a target containing spaces, quotes or
// semicolons cannot change which program runs or which flags it sees.
func BuildArgs(p Profile, target string, vars map[string]string, outFile string) ([]string, error) {
	sub := func(v string) string {
		switch v {
		case "target":
			return target
		case "outfile":
			return outFile
		}
		if val, ok := vars[v]; ok {
			return val
		}
		return ""
	}
	out := make([]string, 0, len(p.Args))
	for _, a := range p.Args {
		if strings.Contains(a, "{{") {
			var b strings.Builder
			rest := a
			for {
				i := strings.Index(rest, "{{")
				if i < 0 {
					b.WriteString(rest)
					break
				}
				b.WriteString(rest[:i])
				rest = rest[i+2:]
				j := strings.Index(rest, "}}")
				if j < 0 {
					b.WriteString("{{")
					b.WriteString(rest)
					break
				}
				name := strings.TrimSpace(rest[:j])
				val := sub(name)
				if val == "" && name != "target" {
					return nil, fmt.Errorf("参数 %q 需要变量 %s 的值，但调用方没有提供", a, name)
				}
				b.WriteString(val)
				rest = rest[j+2:]
			}
			out = append(out, b.String())
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// ResolveBinary finds the executable for a profile. An absolute or relative path
// is accepted as-is; a bare name is looked up on PATH.
func ResolveBinary(bin string) (string, error) {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return "", errors.New("扫描器未配置可执行文件")
	}
	if strings.ContainsAny(bin, `/\`) {
		st, err := os.Stat(bin)
		if err != nil {
			return "", fmt.Errorf("找不到可执行文件 %s: %w", bin, err)
		}
		if st.IsDir() {
			return "", fmt.Errorf("%s 是目录，不是可执行文件", bin)
		}
		return bin, nil
	}
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("PATH 中找不到 %s（请安装或在该扫描器配置里填绝对路径）", bin)
	}
	return p, nil
}

// Available reports whether the profile's binary can be resolved right now.
func Available(p Profile) bool {
	_, err := ResolveBinary(p.Binary)
	return err == nil
}

// Run executes one scan and parses its output. A timeout kills the process and
// returns the partial result with TimedOut set: a scanner that has already found
// something should still contribute it.
func Run(ctx context.Context, spec RunSpec) (*RunOutput, error) {
	bin, err := ResolveBinary(spec.Profile.Binary)
	if err != nil {
		return nil, err
	}
	target := strings.TrimSpace(spec.Target)
	if target == "" {
		return nil, errors.New("target 不能为空")
	}

	tmp, err := os.MkdirTemp("", "artex-scan-*")
	if err != nil {
		return nil, fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmp)
	outFile := tmp + string(os.PathSeparator) + "out.json"

	args, err := BuildArgs(spec.Profile, target, spec.Vars, outFile)
	if err != nil {
		return nil, err
	}

	timeout := DefaultTimeout
	if spec.Profile.TimeoutSeconds > 0 {
		timeout = time.Duration(spec.Profile.TimeoutSeconds) * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out := &RunOutput{StartedAt: time.Now()}
	stdout := &capBuffer{max: MaxOutput}
	stderr := &capBuffer{max: 1 << 20}

	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = os.Environ()

	err = cmd.Run()
	out.FinishedAt = time.Now()
	out.Truncated = stdout.truncated

	if cmd.ProcessState != nil {
		out.ExitCode = cmd.ProcessState.ExitCode()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		out.TimedOut = true
	}

	// A scanner may write its JSON to a file instead of stdout (ffuf does).
	data := stdout.Bytes()
	if len(data) == 0 {
		if b, ferr := os.ReadFile(outFile); ferr == nil {
			data = b
		}
	}
	out.Stderr = Clip(stderr.String(), 4000)

	if err != nil && len(data) == 0 && !out.TimedOut {
		return out, fmt.Errorf("扫描器退出异常（exit %d）: %s", out.ExitCode, out.Stderr)
	}
	if out.TimedOut && len(data) == 0 {
		return out, fmt.Errorf("扫描超时（%s），未产生输出", timeout)
	}

	out.Stdout = data
	r := Parse(spec.Profile.Format, spec.Profile.Name, target, data)
	r.Warnings = append(r.Warnings, stdout.warnings...)
	out.Result = r
	return out, nil
}

// capBuffer keeps at most max bytes and remembers that it had to drop the rest.
type capBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
	warnings  []string
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	if c.buf.Len() >= c.max {
		c.truncated = true
		return n, nil
	}
	if room := c.max - c.buf.Len(); len(p) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return n, nil
	}
	c.buf.Write(p)
	return n, nil
}

func (c *capBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

func (c *capBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}
