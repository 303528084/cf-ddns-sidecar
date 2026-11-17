package web

import (
	"fmt"
	"strings"
)

// MinPasswordLen 是后台登录密码的最短长度。
//
// 定在 8 而不是 6：这个后台对所有 IP 开放（以后还会通过隧道放上公网），
// 密码是唯一一道门。6 位纯数字一共一百万种组合，对着登录接口跑几小时就能
// 撞开；8 位字母数字混合的量级完全不同。
const MinPasswordLen = 8

// weakPasswords 是最常见的一批弱密码。铺全量字典没必要，这里只挡
// 「顺手就会填进去」的那几个。
var weakPasswords = map[string]bool{
	"password": true, "passw0rd": true, "p@ssw0rd": true,
	"p@ssword": true, "password1": true,
	"12345678": true, "123456789": true, "1234567890": true,
	"87654321": true, "88888888": true, "66668888": true,
	"qwerty123": true, "qwertyuiop": true, "abc12345": true,
	"admin123": true, "admin888": true, "root1234": true,
	"dashboard": true, "iloveyou": true, "woaini1314": true,
	"a1234567": true, "cfddns": true, "cfddnssidecar": true,
}

// WeakPasswordReason 判断密码够不够用：够用返回空字符串；不够用返回一句
// 可以直接显示给用户看的中文原因（调用方会拼在「新密码」后面）。
//
// 规则刻意少而好懂——用户不是安全工程师，规则太多他只会想办法绕过：
//  1. 至少 8 位；
//  2. 不是常见弱密码；
//  3. 不是同一个字符重复；
//  4. 不是连续上升/下降的序列；
//  5. 纯数字的话至少 10 位（手机号级别的长度）。
func WeakPasswordReason(pw string) string {
	pw = strings.TrimSpace(pw)
	if pw == "" {
		return "不能为空"
	}
	if n := len([]rune(pw)); n < MinPasswordLen {
		return fmt.Sprintf("太短了（现在 %d 位，至少要 %d 位）", n, MinPasswordLen)
	}
	if weakPasswords[strings.ToLower(pw)] {
		return "是最常见的弱密码之一，很容易被猜中"
	}
	if allSameRune(pw) {
		return "全是同一个字符，很容易被猜中"
	}
	if isStraightRun(pw) {
		return "是连续的数字或字母（如 12345678、abcdefgh），很容易被猜中"
	}
	if digitsOnly(pw) && len(pw) < 10 {
		return "是纯数字而且不够长，建议掺入字母"
	}
	return ""
}

// allSameRune 判断整串是不是同一个字符重复（如 11111111、aaaaaaaa）。
func allSameRune(s string) bool {
	r := []rune(s)
	if len(r) == 0 {
		return false
	}
	for _, c := range r[1:] {
		if c != r[0] {
			return false
		}
	}
	return true
}

// isStraightRun 判断整串是不是等差为 +1 / -1 的连续字符。
//
// 字母首尾相接也算（z→a 记作 +1），这样 zabcdefg 这种也会被挡住。
func isStraightRun(s string) bool {
	r := []rune(strings.ToLower(s))
	if len(r) < 3 {
		return false
	}
	up, down := true, true
	for i := 1; i < len(r); i++ {
		d := int(r[i] - r[i-1])
		// z→a 的差是 -25，按「+1 循环」处理
		if d != 1 && d != -25 {
			up = false
		}
		if d != -1 && d != 25 {
			down = false
		}
		if !up && !down {
			return false
		}
	}
	return up || down
}

// digitsOnly 判断是不是纯数字。
func digitsOnly(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
