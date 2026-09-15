package subfinder

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"subexposure/internal/scope"
	"time"
)

const MaxHosts = 10000

func Enumerate(ctx context.Context, path, root, seed string, disabled bool) ([]string, error) {
	hosts := map[string]bool{seed: true}
	if !disabled {
		hosts[root] = true
	}
	if !disabled {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, "-silent", "-d", root)
		cmd.WaitDelay = time.Second
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		cmd.Stderr = io.Discard
		if err = cmd.Start(); err != nil {
			return nil, fmt.Errorf("cannot start subfinder; install it or use --no-subdomains")
		}
		scanner := bufio.NewScanner(io.LimitReader(pipe, 4*1024*1024+1))
		scanner.Buffer(make([]byte, 4096), 4096)
		bytes := 0
		var parseErr error
		for scanner.Scan() {
			bytes += len(scanner.Bytes()) + 1
			if bytes > 4*1024*1024 {
				parseErr = fmt.Errorf("subfinder output limit exceeded")
				break
			}
			h, e := scope.Normalize(scanner.Text())
			if e == nil && scope.Contains(root, h) {
				hosts[h] = true
			}
			if len(hosts) > MaxHosts {
				parseErr = fmt.Errorf("host limit exceeded (%d)", MaxHosts)
				break
			}
		}
		if scanner.Err() != nil {
			parseErr = fmt.Errorf("invalid or oversized subfinder output")
		}
		if parseErr != nil {
			cancel()
		}
		waitErr := cmd.Wait()
		if parseErr != nil {
			return nil, parseErr
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if waitErr != nil {
			return nil, fmt.Errorf("subfinder failed")
		}
	}
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out, nil
}
