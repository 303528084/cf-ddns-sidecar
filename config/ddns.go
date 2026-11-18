package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EnvFile 是 DDNS 密钥文件（KEY=VALUE），放在数据目录里。
// 界面上的「域名解析」配置会写回这个文件，用户也可以用文本编辑器改。
const EnvFile = "ddns.env"

// EnvFilePath 返回 ddns.env 的绝对路径（与 config.json 同目录）。
func EnvFilePath() string {
	return filepath.Join(filepath.Dir(resolvePath()), EnvFile)
}

// LoadEnvFile 解析 KEY=VALUE 文件：支持 # 注释、空行、值两侧引号、CRLF。
// 文件不存在时返回空表而不报错。
func LoadEnvFile(path string) map[string]string {
	kv := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return kv
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if key != "" {
			kv[key] = val
		}
	}
	return kv
}

// SaveEnvFile 把 map 写回 KEY=VALUE 文件（按 key 排序，覆盖写）。
// 只用于程序内部更新密钥：值来自界面输入，写入前已做换行清理。
func SaveEnvFile(path string, kv map[string]string) error {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# 本文件由应用自动维护，也可以在文本编辑器里直接修改\n")
	for _, k := range keys {
		v := strings.ReplaceAll(kv[k], "\n", "")
		v = strings.ReplaceAll(v, "\r", "")
		b.WriteString(k + "=" + v + "\n")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// 0644 而不是 0600：这个文件有两个不同用户在读写。
	// 程序以 app 用户跑，飞牛生命周期脚本以 docker-<appname> 用户跑。
	// 用 0600 的话脚本读不到内容，它的 set_kv 会「读了个空」然后把整个文件
	// 重写成只剩它要写的那一项——用户填的所有密钥会被静默冲掉。
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// UpdateEnvFile 只改指定 key 的行，其余内容（注释、顺序、其他 key）原样保留。
// 唯一的例外是空行：首尾的空行会被去掉、连续空行会并成一个（老版本每保存
// 一次末尾就多一个空行，攒下来会让文件读不下去）。
//
// 为什么不用 SaveEnvFile 整体重写：ddns.env 里可能有用户自己写的注释和
// 被注释掉的备用密钥，整体重写会把它们冲掉。
//
// 替换落在哪一行，有两条必须守住的规矩（都是 2026-11-18 修备份那次连出来的）：
//  1. **只改未注释的行**。`#CF_API_TOKEN=旧的` 是用户自己留的备份，`LoadEnvFile`
//     本来就跳过 `#` 开头的行——去「接管」它既毁了备份，又对生效值毫无影响。
//  2. **同一个 key 有多个未注释行时，改最后一行**。文件语义上最后一行生效
//     （`LoadEnvFile` 后写覆盖先写），改中间那行等于「写进了一个不生效的位置」：
//     界面说保存成功、实际用的还是旧值，这种失败最查不出来。
//
// 以前两条都不对（第一条 `strings.TrimPrefix(trimmed, "#")` 就接管注释行，
// 而且取的是最先匹配的那行），所以「用户把旧令牌注释掉、在下面填新的」这个
// 最自然的换密钥动作，结果恰好是旧令牌继续生效。
func UpdateEnvFile(path string, kv map[string]string) error {
	if len(kv) == 0 {
		return nil
	}
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	lines := strings.Split(string(existing), "\n")
	// 去掉首尾空行：不这么做的话每保存一次末尾就多一个空行，越攒越多
	// （`Split` 结尾的那个空元素会再写成一个换行）。
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	// 连续空行并成一个：老版本每保存一次末尾就多一个空行，这些空行在后来
	// 追加新 key 之后变成了文件中间的一堆空白（真机 ddns.env 上见过连着一
	// 二十行）。只动空行，别的字符一个不碰，文件至少还能读。
	collapsed := lines[:0]
	for _, l := range lines {
		if strings.TrimSpace(l) == "" && len(collapsed) > 0 &&
			strings.TrimSpace(collapsed[len(collapsed)-1]) == "" {
			continue
		}
		collapsed = append(collapsed, l)
	}
	lines = collapsed

	// 先算出「每个要改的 key 落在第几行」：取最后一条未注释的同名行。
	lastAt := make(map[string]int, len(kv))
	for i, line := range lines {
		t := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, _, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		if k = strings.TrimSpace(k); hasKey(kv, k) {
			lastAt[k] = i // 后出现的覆盖前面，正是「最后一行生效」
		}
	}
	replaceAt := make(map[int]string, len(lastAt))
	for k, i := range lastAt {
		replaceAt[i] = k
	}

	done := make(map[string]bool, len(kv))
	var b strings.Builder
	for i, line := range lines {
		text := strings.TrimSuffix(line, "\r")
		if k, ok := replaceAt[i]; ok && !done[k] {
			b.WriteString(k + "=" + sanitizeEnvValue(kv[k]) + "\n")
			done[k] = true
			continue
		}
		b.WriteString(text + "\n")
	}

	// 文件里没有的 key 追加到末尾
	keys := make([]string, 0, len(kv))
	for k := range kv {
		if !done[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k + "=" + sanitizeEnvValue(kv[k]) + "\n")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// 0644 的理由同 SaveEnvFile：生命周期脚本是另一个用户，必须能读。
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func hasKey(m map[string]string, k string) bool {
	_, ok := m[k]
	return ok
}

// sanitizeEnvValue 去掉换行，避免一个值把文件结构撑坏。
func sanitizeEnvValue(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	return strings.ReplaceAll(v, "\r", "")
}

// 各服务商需要的密钥键名（与 ddns.env 里的变量名一致）。
var RequiredEnvByProvider = map[string][]string{
	"cloudflare": {"CF_API_TOKEN", "CF_ZONE_ID"},
	"aliyun":     {"ALIYUN_ACCESS_KEY_ID", "ALIYUN_ACCESS_KEY_SECRET"},
	"dnspod":     {"TENCENT_SECRET_ID", "TENCENT_SECRET_KEY"},
	"huawei":     {"HUAWEI_AK", "HUAWEI_SK", "HUAWEI_ZONE_ID"},
}

// OptionalEnvByProvider 各家可选键（多级公共后缀时才需要）。
var OptionalEnvByProvider = map[string][]string{
	"aliyun": {"ALIYUN_ROOT_DOMAIN"},
	"dnspod": {"DNSPOD_ROOT_DOMAIN"},
}

// DDNCredentials 按服务商收集密钥：进程环境变量优先，其次 ddns.env 文件。
// 返回的 map 直接喂给 ddns.New。
func DDNCredentials() map[string]string {
	fileEnv := LoadEnvFile(EnvFilePath())
	out := make(map[string]string)
	for _, group := range [][]string{flatValues(RequiredEnvByProvider), flatValues(OptionalEnvByProvider)} {
		for _, name := range group {
			if v := strings.TrimSpace(os.Getenv(name)); v != "" {
				out[name] = v
			} else if v, ok := fileEnv[name]; ok && v != "" {
				out[name] = v
			}
		}
	}
	return out
}

// MissingCredentials 返回当前服务商缺失的密钥名列表（用于界面提示）。
func MissingCredentials(provider string) []string {
	creds := DDNCredentials()
	var missing []string
	for _, name := range RequiredEnvByProvider[provider] {
		if creds[name] == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

func flatValues(m map[string][]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, vs := range m {
		for _, v := range vs {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// AllCredentialKeys 返回所有已知的密钥变量名（四家的必需项 + 可选项），已排序。
//
// 用途是白名单：导入别人的配置备份时，只允许写这些 key 进 ddns.env。
// 不这么卡的话，一个手改过的 json 就能往密钥文件里塞任意变量名。
func AllCredentialKeys() []string {
	seen := make(map[string]bool)
	var out []string
	for _, group := range [][]string{flatValues(RequiredEnvByProvider), flatValues(OptionalEnvByProvider)} {
		for _, k := range group {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}
