package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

//go:embed static/*
var staticFiles embed.FS

// 配置结构
type Config struct {
	Server struct {
		Port     int    `yaml:"port"`
		Password string `yaml:"password"`
	} `yaml:"server"`
	SpeedLimit struct {
		Enabled      bool  `yaml:"enabled"`
		NormalSpeed  int64 `yaml:"normal_speed"`
		LimitedSpeed int64 `yaml:"limited_speed"`
	} `yaml:"speed_limit"`
}

// PikPak API 请求参数
type PikPakDownloadRequest struct {
	FileID       string `json:"file_id"`
	AccessToken  string `json:"access_token"`
	UserAgent    string `json:"user_agent"`
	DeviceID     string `json:"device_id"`
	CaptchaToken string `json:"captcha_token"`
}

// PikPak API 响应结构
type PikPakFileResponse struct {
	WebContentLink string `json:"web_content_link"`
	Medias         []struct {
		MediaID   string `json:"media_id"`
		MediaName string `json:"media_name"`
		Video     struct {
			Height     int     `json:"height"`
			Width      int     `json:"width"`
			Duration   int     `json:"duration"`
			BitRate    int     `json:"bit_rate"`
			FrameRate  float64 `json:"frame_rate"`
			VideoCodec string  `json:"video_codec"`
			AudioCodec string  `json:"audio_codec"`
			VideoType  string  `json:"video_type"`
		} `json:"video"`
		Link struct {
			URL    string `json:"url"`
			Token  string `json:"token"`
			Expire string `json:"expire"`
		} `json:"link"`
		NeedMoreQuota  bool     `json:"need_more_quota"`
		VipTypes       []string `json:"vip_types"`
		RedirectLink   string   `json:"redirect_link"`
		IconLink       string   `json:"icon_link"`
		IsDefault      bool     `json:"is_default"`
		Priority       int      `json:"priority"`
		IsOrigin       bool     `json:"is_origin"`
		ResolutionName string   `json:"resolution_name"`
		IsVisible      bool     `json:"is_visible"`
		Category       string   `json:"category"`
	} `json:"medias"`
}

var (
	config Config
	stats  = &Stats{
		ActiveUsers: make(map[string]*UserStats),
		URLStats:    make(map[string]*URLStat),
		LastUpdate:  time.Now(),
	}
	db *sql.DB
)

// 初始化数据库
func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "stats.db")
	if err != nil {
		return fmt.Errorf("打开数据库失败: %v", err)
	}

	// 创建URL统计表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS url_stats (
			domain TEXT PRIMARY KEY,
			download_count INTEGER,
			total_bytes INTEGER,
			last_used DATETIME
		)
	`)
	if err != nil {
		return fmt.Errorf("创建URL统计表失败: %v", err)
	}

	// 创建总流量统计表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS total_stats (
			id INTEGER PRIMARY KEY,
			total_bytes INTEGER
		)
	`)
	if err != nil {
		return fmt.Errorf("创建总流量统计表失败: %v", err)
	}

	// 初始化总流量记录
	_, err = db.Exec(`
		INSERT OR IGNORE INTO total_stats (id, total_bytes) VALUES (1, 0)
	`)
	if err != nil {
		return fmt.Errorf("初始化总流量记录失败: %v", err)
	}

	// 加载已存储的统计数据
	return loadStats()
}

// 加载统计数据
func loadStats() error {
	// 加载URL统计
	rows, err := db.Query("SELECT domain, download_count, total_bytes, last_used FROM url_stats")
	if err != nil {
		return fmt.Errorf("查询URL统计失败: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		var stat URLStat
		var lastUsed string
		err := rows.Scan(&domain, &stat.DownloadCount, &stat.TotalBytes, &lastUsed)
		if err != nil {
			return fmt.Errorf("读取URL统计失败: %v", err)
		}
		stat.URL = domain
		stat.LastUsed, _ = time.Parse("2006-01-02 15:04:05", lastUsed)
		stats.URLStats[domain] = &stat
	}

	// 加载总流量
	var totalBytes int64
	err = db.QueryRow("SELECT total_bytes FROM total_stats WHERE id = 1").Scan(&totalBytes)
	if err != nil {
		return fmt.Errorf("读取总流量失败: %v", err)
	}
	stats.TotalBytes = totalBytes

	return nil
}

// 保存URL统计
func (s *Stats) SaveURLStats(domain string, stat *URLStat) error {
	_, err := db.Exec(`
		INSERT INTO url_stats (domain, download_count, total_bytes, last_used)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			download_count = ?,
			total_bytes = ?,
			last_used = ?
	`,
		domain, stat.DownloadCount, stat.TotalBytes, stat.LastUsed.Format("2006-01-02 15:04:05"),
		stat.DownloadCount, stat.TotalBytes, stat.LastUsed.Format("2006-01-02 15:04:05"),
	)
	return err
}

// 保存总流量
func (s *Stats) SaveTotalBytes() error {
	_, err := db.Exec("UPDATE total_stats SET total_bytes = ? WHERE id = 1", s.TotalBytes)
	return err
}

// 加载配置文件
func loadConfig() error {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	return nil
}

type ProxyConfig struct {
	URL    string `json:"url"`
	UA     string `json:"ua"`
	Cookie string `json:"cookie"`
	XS     bool   `json:"xs"`
}

type DownloadInfo struct {
	URL      string `json:"url"`
	Filename string `json:"filename"`
	UA       string `json:"ua"`
}

// 计算签名
func calculateSignature(url, ua, cookie string, xs bool) string {
	xsStr := "0"
	if xs {
		xsStr = "1"
	}
	data := fmt.Sprintf("%s%s%s%s%s", url, ua, cookie, xsStr, config.Server.Password)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// 计算下载链接签名
func calculateDownloadSign(urlPath string, timestamp int64) string {
	data := fmt.Sprintf("%s%d%s", urlPath, timestamp, config.Server.Password)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// 计算文件访问签名
func calculateFileSign(filename string, timestamp int64) string {
	data := fmt.Sprintf("%s%d%s", filename, timestamp, config.Server.Password)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// 从URL响应头获取文件名
func getFilenameFromURL(targetURL, userAgent string) string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		return ""
	}

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0")
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// 从 Content-Disposition 头获取文件名
	contentDisposition := resp.Header.Get("Content-Disposition")
	if contentDisposition != "" {
		// 优先处理 filename*=UTF-8''xxx 格式（RFC 5987）
		if idx := strings.Index(contentDisposition, "filename*=UTF-8''"); idx != -1 {
			filename := contentDisposition[idx+17:]
			// 去除可能的分号和空格
			if semicolonIdx := strings.Index(filename, ";"); semicolonIdx != -1 {
				filename = filename[:semicolonIdx]
			}
			filename = strings.TrimSpace(filename)
			if decoded, err := url.QueryUnescape(filename); err == nil {
				filename = decoded
			}
			if filename != "" {
				return filename
			}
		}
		// 处理 filename="xxx" 或 filename=xxx 格式
		if idx := strings.Index(contentDisposition, "filename="); idx != -1 {
			filename := contentDisposition[idx+9:]
			// 去除引号
			filename = strings.Trim(filename, `"'`)
			// 去除可能的分号和空格
			if semicolonIdx := strings.Index(filename, ";"); semicolonIdx != -1 {
				filename = filename[:semicolonIdx]
			}
			filename = strings.TrimSpace(filename)
			// URL解码
			if decoded, err := url.QueryUnescape(filename); err == nil {
				filename = decoded
			}
			if filename != "" {
				return filename
			}
		}
	}

	// 如果从响应头获取不到，尝试从URL路径中提取
	parsedURL, err := url.Parse(targetURL)
	if err == nil {
		path := parsedURL.Path
		if path != "" && path != "/" {
			parts := strings.Split(path, "/")
			if len(parts) > 0 {
				lastPart := parts[len(parts)-1]
				if lastPart != "" {
					// URL解码
					if decoded, err := url.QueryUnescape(lastPart); err == nil {
						return decoded
					}
					return lastPart
				}
			}
		}
	}

	return ""
}

// 生成AES密钥（从密码生成32字节密钥）
func generateAESKey(password string) []byte {
	hash := md5.Sum([]byte(password))
	key := make([]byte, 32)
	copy(key, hash[:])
	// 如果密码长度超过16字节，继续填充
	if len(password) > 16 {
		hash2 := md5.Sum([]byte(password + "salt"))
		copy(key[16:], hash2[:])
	}
	return key
}

// AES加密
func encryptAES(plaintext []byte) (string, error) {
	key := generateAESKey(config.Server.Password)
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

// AES解密
func decryptAES(ciphertextStr string) ([]byte, error) {
	// 解码base64
	ciphertext, err := base64.URLEncoding.DecodeString(ciphertextStr)
	if err != nil {
		return nil, err
	}

	key := generateAESKey(config.Server.Password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("密文太短")
	}

	// 提取IV
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// 解密
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 去除PKCS7填充
	return pkcs7Unpadding(plaintext), nil
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

// PKCS7去填充
func pkcs7Unpadding(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return data
	}
	return data[:(length - unpadding)]
}

// 验证密码中间件
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		password := c.GetHeader("X-Proxy-Password")
		if password != config.Server.Password {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "密码验证失败",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// 测试链接处理函数
func testConnection(c *gin.Context) {
	var proxyConfig ProxyConfig
	if err := c.ShouldBindJSON(&proxyConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求参数",
		})
		return
	}

	signature := calculateSignature(proxyConfig.URL, proxyConfig.UA, proxyConfig.Cookie, proxyConfig.XS)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"url":       proxyConfig.URL,
			"ua":        proxyConfig.UA,
			"cookie":    proxyConfig.Cookie,
			"xs":        proxyConfig.XS,
			"signature": signature,
			"timestamp": time.Now().Unix(),
		},
	})
}

// 添加下载链接
func addDownload(c *gin.Context) {
	var downloadInfo DownloadInfo
	if err := c.ShouldBindJSON(&downloadInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求参数",
		})
		return
	}

	timestamp := time.Now().Unix()

	// 如果filename为空，尝试从URL响应头获取
	filename := downloadInfo.Filename
	if filename == "" {
		filename = getFilenameFromURL(downloadInfo.URL, downloadInfo.UA)
		// 如果还是获取不到，使用默认文件名
		if filename == "" {
			filename = "download"
		}
	}

	downloadData := struct {
		URL      string `json:"url"`
		UA       string `json:"ua"`
		Filename string `json:"filename"`
	}{
		URL:      downloadInfo.URL,
		UA:       downloadInfo.UA,
		Filename: filename,
	}

	jsonData, err := json.Marshal(downloadData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "处理下载信息失败",
		})
		return
	}

	// 使用AES加密而不是base64
	urlData, err := encryptAES(jsonData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "加密失败",
		})
		return
	}
	downloadPath := fmt.Sprintf("/download/%s", urlData)
	sign := calculateDownloadSign(downloadPath, timestamp)

	// 构建完整的URL（域名+路径）
	scheme := "http"
	if c.GetHeader("X-Forwarded-Proto") == "https" || c.Request.TLS != nil {
		scheme = "https"
	}
	host := c.GetHeader("Host")
	if host == "" {
		host = c.Request.Host
	}
	fullURL := fmt.Sprintf("%s://%s%s?sign=%s&time=%d", scheme, host, downloadPath, sign, timestamp)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"download_url": fullURL,
		},
	})
}

// 处理下载请求
func handleDownload(c *gin.Context) {
	urlData := c.Param("urlData")
	sign := c.Query("sign")
	timestamp, err := strconv.ParseInt(c.Query("time"), 10, 64)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的时间戳",
		})
		return
	}

	downloadPath := fmt.Sprintf("/download/%s", urlData)
	expectedSign := calculateDownloadSign(downloadPath, timestamp)

	if sign != expectedSign {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "签名无效",
		})
		return
	}

	// 使用AES解密
	decodedBytes, err := decryptAES(urlData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "解密失败",
		})
		return
	}

	var downloadData struct {
		URL      string `json:"url"`
		UA       string `json:"ua"`
		Filename string `json:"filename"`
	}

	if err := json.Unmarshal(decodedBytes, &downloadData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的下载信息",
		})
		return
	}

	fileTimestamp := time.Now().Unix()
	fileSign := calculateFileSign(downloadData.Filename, fileTimestamp)

	// urlData已经是AES加密后的字符串，直接使用，不需要base64
	// 但作为路径参数需要进行URL编码
	redirectURL := fmt.Sprintf("/file/%s?filename=%s&xsign=%s&time=%d",
		url.QueryEscape(urlData),
		url.QueryEscape(downloadData.Filename),
		fileSign,
		fileTimestamp,
	)

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// 限速读取器
type rateLimitedReader struct {
	reader      io.Reader
	bytesPerSec int64
	lastRead    time.Time
	bytesRead   int64
}

func (r *rateLimitedReader) Read(p []byte) (n int, err error) {
	if r.bytesPerSec <= 0 {
		return r.reader.Read(p)
	}

	// 如果是首次读取，初始化lastRead
	if r.lastRead.IsZero() {
		r.lastRead = time.Now()
		r.bytesRead = 0
	}

	// 计算自上次读取以来应该经过的时间
	expectedTime := time.Duration(float64(r.bytesRead) / float64(r.bytesPerSec) * float64(time.Second))
	actualTime := time.Since(r.lastRead)

	// 如果读取太快，需要等待
	if actualTime < expectedTime {
		sleepTime := expectedTime - actualTime
		if sleepTime > 100*time.Millisecond {
			log.Printf("[限速] 降速等待: %v", sleepTime)
		}
		time.Sleep(sleepTime)
	}

	// 读取数据
	n, err = r.reader.Read(p)
	if n > 0 {
		r.bytesRead += int64(n)
		// 每10MB记录一次当前速度
		if r.bytesRead%(10*1024*1024) < int64(n) {
			elapsed := time.Since(r.lastRead)
			currentSpeed := float64(r.bytesRead) / elapsed.Seconds() / 1024 / 1024
			log.Printf("[限速] 当前速度: %.2f MB/s, 目标速度: %.2f MB/s",
				currentSpeed, float64(r.bytesPerSec)/1024/1024)
		}
	}

	return
}

// 统计信息
type Stats struct {
	mutex           sync.RWMutex
	ActiveUsers     map[string]*UserStats `json:"active_users"`
	URLStats        map[string]*URLStat   `json:"url_stats"`
	TotalBytes      int64                 `json:"total_bytes"`
	CurrentUpload   int64                 `json:"current_upload"`
	CurrentDownload int64                 `json:"current_download"`
	LastUpdate      time.Time             `json:"-"`
}

type UserStats struct {
	IP            string    `json:"ip"`
	LastSeen      time.Time `json:"last_seen"`
	CurrentSpeed  int64     `json:"current_speed"`
	TotalBytes    int64     `json:"total_bytes"`
	DownloadCount int       `json:"download_count"`
}

type URLStat struct {
	URL           string    `json:"url"`
	DownloadCount int       `json:"download_count"`
	TotalBytes    int64     `json:"total_bytes"`
	LastUsed      time.Time `json:"last_used"`
}

// 更新URL统计
func (s *Stats) UpdateURLStats(urlStr string, bytes int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	domain := parsedURL.Host

	if _, exists := s.URLStats[domain]; !exists {
		s.URLStats[domain] = &URLStat{
			URL: domain,
		}
	}

	urlStat := s.URLStats[domain]
	urlStat.DownloadCount++
	urlStat.TotalBytes += bytes
	urlStat.LastUsed = time.Now()

	// 保存到数据库
	if err := s.SaveURLStats(domain, urlStat); err != nil {
		log.Printf("保存URL统计失败: %v", err)
	}
}

// 更新用户统计
func (s *Stats) UpdateUserStats(ip string, bytes int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.ActiveUsers[ip]; !exists {
		s.ActiveUsers[ip] = &UserStats{
			IP:       ip,
			LastSeen: time.Now(),
		}
	}

	user := s.ActiveUsers[ip]
	user.LastSeen = time.Now()
	user.TotalBytes += bytes

	duration := time.Since(s.LastUpdate).Seconds()
	if duration > 0 {
		if bytes > 0 {
			user.CurrentSpeed = int64(float64(bytes) / duration)
			s.CurrentDownload = int64(float64(bytes) / duration)
		} else {
			user.CurrentSpeed = 0
			s.CurrentDownload = 0
		}
	}

	user.DownloadCount++
	s.TotalBytes += bytes
	s.LastUpdate = time.Now()

	// 保存总流量到数据库
	if err := s.SaveTotalBytes(); err != nil {
		log.Printf("保存总流量失败: %v", err)
	}
}

func (s *Stats) CleanupOldUsers() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	threshold := time.Now().Add(-5 * time.Minute)
	for ip, user := range s.ActiveUsers {
		if user.LastSeen.Before(threshold) {
			delete(s.ActiveUsers, ip)
		}
	}
}

// 获取统计信息的API
func getStats(c *gin.Context) {
	stats.mutex.RLock()
	defer stats.mutex.RUnlock()

	// 如果超过5秒没有新的数据传输，将当前速度设为0
	if time.Since(stats.LastUpdate) > 5*time.Second {
		stats.CurrentDownload = 0
		for _, user := range stats.ActiveUsers {
			user.CurrentSpeed = 0
		}
	}

	c.JSON(http.StatusOK, stats)
}

// 处理文件服务请求
func handleFile(c *gin.Context) {
	urlData := c.Param("urlData")
	filename := c.Query("filename")
	xsign := c.Query("xsign")
	timestamp, err := strconv.ParseInt(c.Query("time"), 10, 64)
	xs := c.Query("xs") == "1"

	// 缩短日志输出
	log.Printf("[下载] 开始处理: %s, 限速模式: %v", filename, xs)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的时间戳",
		})
		return
	}

	expectedSign := calculateFileSign(filename, timestamp)
	if xsign != expectedSign {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "文件访问签名无效",
		})
		return
	}

	// 使用AES解密
	decodedBytes, err := decryptAES(urlData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "解密失败",
		})
		return
	}

	var downloadData struct {
		URL      string `json:"url"`
		UA       string `json:"ua"`
		Filename string `json:"filename"`
	}

	if err := json.Unmarshal(decodedBytes, &downloadData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的下载信息",
		})
		return
	}

	// 创建一个具有超时设置的客户端
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true, // 对于大文件传输禁用压缩可能提高性能
		},
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", downloadData.URL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建请求失败",
		})
		return
	}

	req.Header.Set("User-Agent", downloadData.UA)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity") // 避免使用压缩，可能会提高传输速度
	req.Header.Set("Connection", "keep-alive")

	// 只有在未启用限速的情况下才支持多线程下载
	if !config.SpeedLimit.Enabled {
		// 处理Range请求头，支持多线程下载
		if rangeHeader := c.GetHeader("Range"); rangeHeader != "" {
			// 截取Range头的前30个字符以避免过长日志
			displayRange := rangeHeader
			if len(rangeHeader) > 30 {
				displayRange = rangeHeader[:30] + "..."
			}
			log.Printf("[下载] Range请求: %s", displayRange)
			req.Header.Set("Range", rangeHeader)
		} else {
			log.Printf("[下载] 单线程下载")
		}
	} else {
		log.Printf("[下载] 限速模式已启用，禁用多线程")
	}

	// 截取URL，只显示域名而不是完整URL
	parsedURL, _ := url.Parse(downloadData.URL)
	log.Printf("[下载] 请求源站: %s", parsedURL.Host)

	startTime := time.Now()
	resp, err := client.Do(req)
	log.Printf("[下载] 源站响应: %v", time.Since(startTime))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "下载文件失败",
		})
		return
	}
	defer resp.Body.Close()

	// 判断是否为Range请求的响应
	isPartialContent := resp.StatusCode == http.StatusPartialContent
	log.Printf("[下载] 状态码: %d, 部分内容: %v", resp.StatusCode, isPartialContent)

	if !isPartialContent && resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"message": fmt.Sprintf("源服务器返回错误状态码: %d", resp.StatusCode),
		})
		return
	}

	// 设置响应头
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, url.QueryEscape(downloadData.Filename)))
	c.Header("Content-Type", resp.Header.Get("Content-Type"))

	// 只有在未启用限速的情况下才提供多线程下载支持
	if !config.SpeedLimit.Enabled {
		// 复制所有与Range相关的响应头
		c.Header("Accept-Ranges", "bytes")
		if resp.Header.Get("Content-Range") != "" {
			contentRange := resp.Header.Get("Content-Range")
			// 截取Content-Range头，避免过长日志
			displayRange := contentRange
			if len(contentRange) > 30 {
				displayRange = contentRange[:30] + "..."
			}
			c.Header("Content-Range", contentRange)
			log.Printf("[下载] Content-Range: %s", displayRange)
		}
	}

	if resp.Header.Get("Content-Length") != "" {
		contentLength := resp.Header.Get("Content-Length")
		c.Header("Content-Length", contentLength)

		// 将字节数转换为MB显示
		bytes, _ := strconv.ParseInt(contentLength, 10, 64)
		fileSizeMB := float64(bytes) / 1024 / 1024
		log.Printf("[下载] 文件大小: %.2f MB", fileSizeMB)
	}

	// 设置正确的状态码
	c.Status(resp.StatusCode)

	var reader io.Reader = resp.Body
	if config.SpeedLimit.Enabled {
		speed := config.SpeedLimit.NormalSpeed
		if xs {
			speed = config.SpeedLimit.LimitedSpeed
		}
		speedMB := float64(speed) / 1024 / 1024
		log.Printf("[下载] 启用限速: %.2f MB/s", speedMB)
		reader = &rateLimitedReader{
			reader:      resp.Body,
			bytesPerSec: speed,
		}
	} else {
		log.Printf("[下载] 不限速")
	}

	// 仅在非频繁场景下更新数据库统计
	updateStats := func(bytes int64) {
		// 每10MB更新一次统计，减少更新频率
		const updateThreshold = 10 * 1024 * 1024

		// 对传输的字节进行累加
		atomic.AddInt64(&stats.TotalBytes, bytes)

		// 只有达到阈值才进行完整统计更新
		if atomic.LoadInt64(&stats.TotalBytes)%updateThreshold < int64(bytes) {
			ip := c.ClientIP()
			stats.UpdateUserStats(ip, bytes)
			stats.UpdateURLStats(downloadData.URL, bytes)
		}
	}

	ip := c.ClientIP()
	counter := &CountingReader{
		Reader: reader,
		OnRead: updateStats,
	}

	log.Printf("[下载] 开始传输数据")
	transferStart := time.Now()

	// 使用更大的缓冲区进行数据传输
	buf := make([]byte, 256*1024) // 256KB缓冲区，比默认的32KB大很多
	written, err := io.CopyBuffer(c.Writer, counter, buf)

	transferDuration := time.Since(transferStart)
	transferSpeed := float64(written) / transferDuration.Seconds() / 1024 / 1024
	writtenMB := float64(written) / 1024 / 1024
	log.Printf("[下载] 传输完成: %.2f MB, 耗时: %v, 速度: %.2f MB/s", writtenMB, transferDuration, transferSpeed)

	// 确保最终的统计数据被正确记录
	stats.UpdateUserStats(ip, 0)
	stats.UpdateURLStats(downloadData.URL, 0)

	if err != nil {
		if strings.Contains(err.Error(), "connection was aborted") ||
			strings.Contains(err.Error(), "connection was forcibly closed") {
			log.Printf("[下载] 客户端断开连接")
		} else {
			log.Printf("[下载] 传输错误: %v", err)
		}
	}
}

// HTTP代理请求结构
type ProxyRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// 处理HTTP代理请求
func handleProxyRequest(c *gin.Context) {
	var req ProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求参数",
		})
		return
	}

	// 验证URL
	if req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "URL不能为空",
		})
		return
	}

	// 默认方法为GET
	if req.Method == "" {
		req.Method = "GET"
	}

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 创建请求体
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	// 创建HTTP请求
	proxyReq, err := http.NewRequest(req.Method, req.URL, bodyReader)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "创建请求失败: " + err.Error(),
		})
		return
	}

	// 设置请求头
	for key, value := range req.Headers {
		proxyReq.Header.Set(key, value)
	}

	// 如果没有设置User-Agent，使用默认值
	if proxyReq.Header.Get("User-Agent") == "" {
		proxyReq.Header.Set("User-Agent", "MoProxy/1.0")
	}

	log.Printf("[代理] %s %s", req.Method, req.URL)

	// 发送请求
	resp, err := client.Do(proxyReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "请求失败: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// 复制响应头到客户端
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// 设置状态码
	c.Status(resp.StatusCode)

	// 直接流式传输响应体，不包装成JSON
	_, err = io.Copy(c.Writer, resp.Body)
	if err != nil {
		log.Printf("[代理] 传输响应失败: %v", err)
	}
}

// 处理 PikPak 下载请求
func handlePikPakDownload(c *gin.Context) {
	var req PikPakDownloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求参数",
		})
		return
	}

	// 构建 PikPak API 请求
	apiURL := fmt.Sprintf("https://api-drive.mypikpak.net/drive/v1/files/%s", req.FileID)
	pikpakReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建请求失败",
		})
		return
	}

	// 添加查询参数
	q := pikpakReq.URL.Query()
	q.Add("_magic", "2021")
	q.Add("usage", "FETCH")
	q.Add("thumbnail_size", "SIZE_LARGE")
	pikpakReq.URL.RawQuery = q.Encode()

	// 设置请求头
	pikpakReq.Header.Set("Authorization", "Bearer "+req.AccessToken)
	pikpakReq.Header.Set("User-Agent", req.UserAgent)
	pikpakReq.Header.Set("X-Device-ID", req.DeviceID)
	if req.CaptchaToken != "" {
		pikpakReq.Header.Set("X-Captcha-Token", req.CaptchaToken)
	}

	// 发送请求
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(pikpakReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "请求 PikPak API 失败: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "读取响应失败: " + err.Error(),
		})
		return
	}

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		c.JSON(resp.StatusCode, gin.H{
			"success": false,
			"message": fmt.Sprintf("PikPak API 返回错误状态码: %d, 响应: %s", resp.StatusCode, string(body)),
		})
		return
	}

	// 解析响应
	var pikpakResp PikPakFileResponse
	if err := json.Unmarshal(body, &pikpakResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "解析响应失败: " + err.Error(),
		})
		return
	}

	// 返回下载链接
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"web_content_link": pikpakResp.WebContentLink,
			"medias":           pikpakResp.Medias,
		},
	})
}

// 计数器Reader
type CountingReader struct {
	io.Reader
	OnRead func(int64)
}

func (r *CountingReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if n > 0 {
		r.OnRead(int64(n))
	}
	return
}

// 自定义GIN日志中间件，减少冗长的URL日志
func customLoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		// 如果是文件下载路径，只显示路径类型，避免日志过长
		if strings.HasPrefix(path, "/file/") {
			c.Next()
			log.Printf("[GIN] %s | %d | %s | /file/...",
				c.Request.Method,
				c.Writer.Status(),
				time.Since(start))
			return
		}
		if strings.HasPrefix(path, "/download/") {
			c.Next()
			log.Printf("[GIN] %s | %d | %s | /download/...",
				c.Request.Method,
				c.Writer.Status(),
				time.Since(start))
			return
		}

		// 对于其他路径，正常记录查询参数
		raw := c.Request.URL.RawQuery
		c.Next()

		if raw != "" {
			// 限制查询参数长度
			if len(raw) > 50 {
				raw = raw[:50] + "..."
			}
			path = path + "?" + raw
		}

		log.Printf("[GIN] %s | %d | %s | %s",
			c.Request.Method,
			c.Writer.Status(),
			time.Since(start),
			path,
		)
	}
}

func main() {
	// 设置日志格式
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// 初始化数据库
	if err := initDB(); err != nil {
		log.Printf("初始化数据库失败: %v\n", err)
		return
	}
	defer db.Close()

	// 加载配置文件
	if err := loadConfig(); err != nil {
		log.Printf("加载配置文件失败: %v\n", err)
		return
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// 使用自定义日志中间件
	r.Use(customLoggerMiddleware())

	// 使用内置的静态文件
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Printf("加载静态文件失败: %v\n", err)
		return
	}

	r.StaticFS("/static", http.FS(staticFS))

	// 主页路由使用内置的 index.html
	r.GET("/", func(c *gin.Context) {
		indexFile, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "无法加载页面")
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, string(indexFile))
	})

	// 统计接口不需要验证
	r.GET("/api/stats", getStats)

	// 需要密码验证的API路由
	apiGroup := r.Group("/api")
	apiGroup.Use(authMiddleware())
	{
		apiGroup.POST("/test", testConnection)
		apiGroup.POST("/add", addDownload)
		apiGroup.POST("/pikpak/down", handlePikPakDownload)
		apiGroup.POST("/proxy", handleProxyRequest)
	}

	// 下载路由不需要密码验证，因为已经有签名验证
	r.GET("/download/:urlData", handleDownload)
	r.GET("/file/:urlData", handleFile)

	// 启动清理过期用户的goroutine
	go func() {
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			stats.CleanupOldUsers()
		}
	}()

	fmt.Printf("代理服务器启动在 :%d 端口...\n", config.Server.Port)
	r.Run(fmt.Sprintf(":%d", config.Server.Port))
}
