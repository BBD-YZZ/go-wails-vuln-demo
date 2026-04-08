package utils

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

// CmdResult 命令执行结果封装，包含所有关键返回信息
type CmdResult struct {
	Stdout   string        // 标准输出
	Stderr   string        // 标准错误
	ExitCode int           // 退出码（0为成功，非0为失败）
	Error    error         // 执行异常（如命令不存在、超时、权限不足等）
	Duration time.Duration // 执行耗时
}

// CmdOption 命令执行配置项，灵活设置各种执行参数
type CmdOption struct {
	Cmd        string        // 要执行的命令（如ls、dir、ping、python）
	Args       []string      // 命令参数（如["-l", "/tmp"]、["127.0.0.1", "-n", "4"]）
	WorkDir    string        // 命令执行的工作目录（空则使用当前程序工作目录）
	Env        []string      // 执行环境变量（空则继承当前程序环境，格式：KEY=VALUE）
	HideWindow bool          // 是否隐藏命令窗口（仅Windows有效，Linux/macOS忽略）
	Timeout    time.Duration // 执行超时时间（0为不超时）
}

// Exec 核心执行方法，传入配置项，返回执行结果（同步执行）
func Exec(opt CmdOption) *CmdResult {
	start := time.Now()
	res := &CmdResult{}

	// 1. 校验核心参数
	if opt.Cmd == "" {
		res.Error = os.ErrInvalid
		res.Duration = time.Since(start)
		return res
	}

	// 2. 创建上下文（支持超时）
	var ctx context.Context
	var cancel context.CancelFunc
	if opt.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), opt.Timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel() // 无论是否超时，最终取消上下文，释放资源

	// 3. 构建命令
	cmd := exec.CommandContext(ctx, opt.Cmd, opt.Args...)

	// 4. 设置工作目录
	if opt.WorkDir != "" {
		if _, err := os.Stat(opt.WorkDir); err != nil {
			res.Error = err
			res.Duration = time.Since(start)
			return res
		}
		cmd.Dir = opt.WorkDir
	}

	// 5. 设置环境变量
	if len(opt.Env) > 0 {
		cmd.Env = opt.Env
	} else {
		cmd.Env = os.Environ() // 继承当前程序环境变量
	}

	// 6. 跨平台配置：Windows隐藏命令框，Linux/macOS无操作
	if opt.HideWindow && runtime.GOOS == "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true, // 核心：隐藏命令行弹窗
		}
	}

	// 7. 捕获标准输出和标准错误
	stdout, err := cmd.Output()
	if err != nil {
		// 区分「执行异常」和「命令执行后返回非0退出码」
		if exitErr, ok := err.(*exec.ExitError); ok {
			// 命令执行了，但退出码非0，捕获stderr和退出码
			res.Stderr = string(exitErr.Stderr)
			res.ExitCode = exitErr.ExitCode()
		} else {
			// 命令未执行成功（如不存在、权限不足、超时）
			res.Error = err
			res.Duration = time.Since(start)
			return res
		}
	} else {
		// 命令执行成功，退出码为0
		res.ExitCode = 0
	}
	res.Stdout = string(stdout)
	res.Duration = time.Since(start)

	return res
}

// ExecSimple 快速执行方法（极简调用，默认不隐藏窗口、不超时、当前目录、继承环境）
// 适用于简单场景，参数：命令，参数列表
func ExecSimple(cmd string, args ...string) *CmdResult {
	return Exec(CmdOption{
		Cmd:        cmd,
		Args:       args,
		HideWindow: false,
		Timeout:    0,
	})
}

// ExecHideWindow 隐藏窗口执行（仅Windows有效，快速调用）
// 适用于需要静默执行的场景，参数：命令，参数列表
func ExecHideWindow(cmd string, args ...string) *CmdResult {
	return Exec(CmdOption{
		Cmd:        cmd,
		Args:       args,
		HideWindow: true,
		Timeout:    0,
	})
}

// ExecWithTimeout 带超时的执行方法（默认不隐藏窗口）
// 适用于需要防止命令卡死的场景，参数：命令，超时时间，参数列表
func ExecWithTimeout(cmd string, timeout time.Duration, args ...string) *CmdResult {
	return Exec(CmdOption{
		Cmd:        cmd,
		Args:       args,
		HideWindow: false,
		Timeout:    timeout,
	})
}

// ExecAsync 异步执行方法（无返回结果，仅执行业务，适用于无需等待的场景）
// 参数：配置项，执行完成后的回调函数（可传nil，忽略回调）
func ExecAsync(opt CmdOption, callback func(*CmdResult)) {
	go func() {
		res := Exec(opt)
		if callback != nil {
			callback(res)
		}
	}()
}

// IsSuccess 判断命令是否执行成功（退出码0且无执行异常）
func (r *CmdResult) IsSuccess() bool {
	return r.Error == nil && r.ExitCode == 0
}

// GetAllOutput 获取合并后的输出（stdout+stderr），适用于不区分输出类型的场景
func (r *CmdResult) GetAllOutput() string {
	return r.Stdout + r.Stderr
}

// EnvFromMap 将map转换为环境变量切片（格式：KEY=VALUE），方便设置Env
func EnvFromMap(envMap map[string]string) []string {
	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}
	return env
}

// func main() {
// 	// ************************** 场景1：简单执行（Windows/dir | Linux/macOS/ls） **************************
// 	fmt.Println("===== 场景1：简单执行 =====")
// 	var simpleRes *cmdutil.CmdResult
// 	if cmdutil.RuntimeGOOS() == "windows" {
// 		simpleRes = cmdutil.ExecSimple("dir", "C:\\") // Windows列出C盘根目录
// 	} else {
// 		simpleRes = cmdutil.ExecSimple("ls", "-l", "/tmp") // Linux/macOS列出/tmp目录
// 	}
// 	fmt.Printf("是否成功：%t，退出码：%d，标准输出：%s，错误：%v\n", simpleRes.IsSuccess(), simpleRes.ExitCode, simpleRes.Stdout, simpleRes.Error)

// 	// ************************** 场景2：隐藏窗口执行（仅Windows有效，静默执行ping） **************************
// 	fmt.Println("\n===== 场景2：隐藏窗口执行 =====")
// 	hideRes := cmdutil.ExecHideWindow("ping", "127.0.0.1", "-n", "2") // Windows ping 2次
// 	fmt.Printf("是否成功：%t，执行耗时：%v，合并输出：%s\n", hideRes.IsSuccess(), hideRes.Duration, hideRes.GetAllOutput())

// 	// ************************** 场景3：带超时执行（防止命令卡死，超时1秒） **************************
// 	fmt.Println("\n===== 场景3：带超时执行 =====")
// 	timeoutRes := cmdutil.ExecWithTimeout("ping", 1*time.Second, "127.0.0.1", "-n", "10") // 本应执行10次，1秒超时
// 	fmt.Printf("是否成功：%t，错误：%v，退出码：%d\n", timeoutRes.IsSuccess(), timeoutRes.Error, timeoutRes.ExitCode)

// 	// ************************** 场景4：自定义配置执行（带环境变量、工作目录、隐藏窗口） **************************
// 	fmt.Println("\n===== 场景4：自定义配置执行 =====")
// 	customOpt := cmdutil.CmdOption{
// 		Cmd:        "echo", // 测试环境变量
// 		Args:       []string{"$TEST_KEY"},
// 		WorkDir:    "./",   // 工作目录为当前目录
// 		Env:        cmdutil.EnvFromMap(map[string]string{"TEST_KEY": "GoCmdUtil_Success"}), // 自定义环境变量
// 		HideWindow: true,
// 		Timeout:    5 * time.Second,
// 	}
// 	customRes := cmdutil.Exec(customOpt)
// 	fmt.Printf("是否成功：%t，标准输出：%s\n", customRes.IsSuccess(), customRes.Stdout)

// 	// ************************** 场景5：异步执行（无需等待，执行完成后回调） **************************
// 	fmt.Println("\n===== 场景5：异步执行 =====")
// 	asyncOpt := cmdutil.CmdOption{
// 		Cmd:        "ping",
// 		Args:       []string{"127.0.0.1", "-n", "3"},
// 		HideWindow: true,
// 	}
// 	cmdutil.ExecAsync(asyncOpt, func(res *cmdutil.CmdResult) {
// 		fmt.Printf("异步执行完成 - 是否成功：%t，执行耗时：%v\n", res.IsSuccess(), res.Duration)
// 	})

// 	// 等待异步执行完成（实际项目中无需此操作，主线程正常执行即可）
// 	time.Sleep(4 * time.Second)
// 	fmt.Println("\n所有测试完成")
// }
