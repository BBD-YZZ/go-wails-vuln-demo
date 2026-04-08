package utils

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type RandomStringConfig struct {
	Length          int    // 字符集长度
	UseLowercase    bool   // 是否包含小写字母
	UseUppercase    bool   // 是否包含大写字母
	UseDigits       bool   // 是否包含数字
	UseSpecialChars bool   // 是否包含特殊字符
	CustomChars     string // 自定义字符集
	ExcludeChars    bool   // 排除相近字符
}

func DefaultRandomStringConfig() *RandomStringConfig {
	return &RandomStringConfig{
		Length:          12,
		UseLowercase:    true,
		UseUppercase:    true,
		UseDigits:       true,
		UseSpecialChars: false,
	}
}

// 生成字符集
func (r *RandomStringConfig) generateCharSet() string {
	var charSet string
	if r.UseLowercase {
		if r.ExcludeChars {
			charSet += "abcdefghjkmnpqrstuvwxyz" // 排除相似字符 i, l, o,
		} else {
			charSet += "abcdefghijklmnopqrstuvwxyz"
		}
	}

	if r.UseUppercase {
		if r.ExcludeChars {
			charSet += "ABCDEFGHJKLMNPQRSTUVWXYZ" // 排除相似字符 I, O,
		} else {
			charSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		}
	}

	if r.UseDigits {
		if r.ExcludeChars {
			charSet += "23456789" // 排除相似字符 0, 1,
		} else {
			charSet += "0123456789"
		}
	}

	if r.UseSpecialChars {
		charSet += "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~"
	}

	if r.CustomChars != "" {
		charSet += r.CustomChars
	}

	if charSet == "" {
		return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}

	return charSet
}

// Validate 验证随机字符串配置是否有效
func (r *RandomStringConfig) validate() error {
	if r.Length <= 0 {
		return errors.New("长度必须大于0")
	}
	if !r.UseLowercase && !r.UseUppercase && !r.UseDigits && !r.UseSpecialChars && r.CustomChars == "" {
		return errors.New("必须选择包含小写字母、大写字母、数字或特殊字符")
	}
	return nil
}

// 生成随机字符串
func GenerateRandomString(config *RandomStringConfig) (string, error) {
	if config.Length <= 0 {
		return "", errors.New("长度必须大于0")
	}

	charSet := config.generateCharSet()
	if len(charSet) == 0 {
		return "", errors.New("字符集为空")
	}

	charLen := big.NewInt(int64(len(charSet)))
	result := make([]byte, config.Length)
	for i := 0; i < config.Length; i++ {
		randIndex, err := rand.Int(rand.Reader, charLen)
		if err != nil {
			return "", err
		}
		result[i] = charSet[randIndex.Int64()]
	}
	return string(result), nil
}
