package tools

import "errors"

// fake_operator_test.go — 测试用操作员终端（与 guard 包测试同构的本地副本）。

// fakeOperator 测试用操作员（与 guard 包测试同构的本地副本）。
type fakeOperator struct {
	answers []string
	calls   int
	// lastPrompt 记录最近一次询问内容（测试断言用）。
	lastPrompt string
}

func (f *fakeOperator) Ask(prompt string, options []string) (string, error) {
	f.calls++
	f.lastPrompt = prompt
	if f.calls > len(f.answers) {
		return "", errors.New("no answer")
	}
	return f.answers[f.calls-1], nil
}
