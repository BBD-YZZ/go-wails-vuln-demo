package utils

import (
	rands "crypto/rand"
	"encoding/base64"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

func HeaderMap(headers http.Header) map[string]string {
	headerMap := make(map[string]string)
	for key, values := range headers {
		headerMap[key] = strings.Join(values, ", ")
	}
	return headerMap
}

// 方法1: 使用指定字符集
func RandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 初始化随机种子
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

// 方法2: 扩展字符集（包括特殊字符）
func RandomStringWithSpecial(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		"!@#$%^&*()-_=+[]{}|;:,.<>?"

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}

// 方法3: 仅数字
func RandomNumberString(n int) string {
	const numbers = "0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = numbers[r.Intn(len(numbers))]
	}
	return string(b)
}

// 方法1: Base62 字符集（字母+数字）
func CryptoRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rands.Int(rands.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret), nil
}

// 方法2: Base64 编码随机字节
func CryptoRandomBase64String(n int) (string, error) {
	// 计算需要多少字节（Base64编码后长度为 4 * ceil(n/3)）
	bytesNeeded := (n*6 + 7) / 8 // 近似计算

	b := make([]byte, bytesNeeded)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	// 转换为Base64并截取前n个字符
	encoded := base64.URLEncoding.EncodeToString(b)
	if len(encoded) > n {
		return encoded[:n], nil
	}
	return encoded, nil
}

// 生成UUID风格的随机字符串
func RandomUUIDString() string {
	uuidStr := uuid.New().String()
	// 移除连字符
	return strings.ReplaceAll(uuidStr, "-", "")
}

// 生成指定长度的UUID风格字符串
func RandomUUIDStringLength(n int) string {
	uuidStr := uuid.New().String()
	cleanStr := strings.ReplaceAll(uuidStr, "-", "")

	if n > len(cleanStr) {
		// 如果需要的长度大于UUID长度，可以重复拼接
		result := cleanStr
		for len(result) < n {
			result += strings.ReplaceAll(uuid.New().String(), "-", "")
		}
		return result[:n]
	}
	return cleanStr[:n]
}

// 使用sync.Once确保全局随机种子只初始化一次
var (
	globalRand *rand.Rand
	once       sync.Once
)

func initGlobalRand() {
	globalRand = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// 高性能版本，使用全局随机实例
func FastRandomString(n int) string {
	once.Do(initGlobalRand)

	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[globalRand.Intn(len(letters))]
	}
	return string(b)
}

// 使用字节操作的优化版本
func FastRandomStringBytes(n int) string {
	once.Do(initGlobalRand)

	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const (
		letterIdxBits = 6                    // 6 bits to represent 64 possibilities (2^6 = 64)
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)

	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax characters
	for i, cache, remain := n-1, globalRand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = globalRand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
