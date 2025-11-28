package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"time"
)

// ProxySDK 代理下载链接生成SDK
type ProxySDK struct {
	ServerURL string // 服务器地址，例如: https://example.com
	Password  string // 服务器密码
}

// DownloadInfo 下载信息
type DownloadInfo struct {
	URL      string `json:"url"`      // 目标下载URL
	UA       string `json:"ua"`        // User-Agent
	Filename string `json:"filename"` // 文件名（可选，为空时服务器会自动获取）
}

// NewProxySDK 创建新的SDK实例
func NewProxySDK(serverURL, password string) *ProxySDK {
	return &ProxySDK{
		ServerURL: serverURL,
		Password:  password,
	}
}

// 生成AES密钥（从密码生成32字节密钥）
func (sdk *ProxySDK) generateAESKey() []byte {
	hash := md5.Sum([]byte(sdk.Password))
	key := make([]byte, 32)
	copy(key, hash[:])
	// 如果密码长度超过16字节，继续填充
	if len(sdk.Password) > 16 {
		hash2 := md5.Sum([]byte(sdk.Password + "salt"))
		copy(key[16:], hash2[:])
	}
	return key
}

// PKCS7填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// AES加密
func (sdk *ProxySDK) encryptAES(plaintext []byte) (string, error) {
	key := sdk.generateAESKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 使用PKCS7填充
	plaintext = pkcs7Padding(plaintext, aes.BlockSize)

	// 生成随机IV
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// 加密
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// 使用URL-safe base64编码
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// 计算下载链接签名
func (sdk *ProxySDK) calculateDownloadSign(urlPath string, timestamp int64) string {
	data := fmt.Sprintf("%s%d%s", urlPath, timestamp, sdk.Password)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GenerateDownloadURL 生成下载链接
// 参数:
//   - targetURL: 目标下载URL
//   - userAgent: User-Agent（可选，为空时使用默认值）
//   - filename: 文件名（可选，为空时服务器会自动从响应头获取）
//
// 返回完整的下载URL
func (sdk *ProxySDK) GenerateDownloadURL(targetURL, userAgent, filename string) (string, error) {
	// 如果User-Agent为空，使用默认值
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}

	// 构建下载数据
	downloadData := DownloadInfo{
		URL:      targetURL,
		UA:       userAgent,
		Filename: filename,
	}

	// 序列化为JSON
	jsonData, err := json.Marshal(downloadData)
	if err != nil {
		return "", fmt.Errorf("序列化下载信息失败: %v", err)
	}

	// AES加密
	encryptedData, err := sdk.encryptAES(jsonData)
	if err != nil {
		return "", fmt.Errorf("加密失败: %v", err)
	}

	// 生成时间戳和签名
	timestamp := time.Now().Unix()
	downloadPath := fmt.Sprintf("/download/%s", encryptedData)
	sign := sdk.calculateDownloadSign(downloadPath, timestamp)

	// 构建完整URL
	// 对加密数据进行URL编码，确保在路径中安全传输
	encodedData := url.QueryEscape(encryptedData)
	fullURL := fmt.Sprintf("%s/download/%s?sign=%s&time=%d",
		sdk.ServerURL,
		encodedData,
		sign,
		timestamp,
	)

	return fullURL, nil
}

// GenerateDownloadURLWithInfo 使用DownloadInfo结构生成下载链接
func (sdk *ProxySDK) GenerateDownloadURLWithInfo(info DownloadInfo) (string, error) {
	return sdk.GenerateDownloadURL(info.URL, info.UA, info.Filename)
}

