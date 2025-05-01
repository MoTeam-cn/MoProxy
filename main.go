package main

import (
	"crypto/md5"
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
	"sync"
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

	downloadData := struct {
		URL      string `json:"url"`
		UA       string `json:"ua"`
		Filename string `json:"filename"`
	}{
		URL:      downloadInfo.URL,
		UA:       downloadInfo.UA,
		Filename: downloadInfo.Filename,
	}

	jsonData, err := json.Marshal(downloadData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "处理下载信息失败",
		})
		return
	}

	urlData := base64.URLEncoding.EncodeToString(jsonData)
	downloadPath := fmt.Sprintf("/download/%s", urlData)
	sign := calculateDownloadSign(downloadPath, timestamp)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"download_url": fmt.Sprintf("%s?sign=%s&time=%d", downloadPath, sign, timestamp),
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

	decodedBytes, err := base64.URLEncoding.DecodeString(urlData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的URL编码",
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

	redirectURL := fmt.Sprintf("/file/%s?filename=%s&xsign=%s&time=%d",
		urlData,
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
}

func (r *rateLimitedReader) Read(p []byte) (n int, err error) {
	if r.bytesPerSec <= 0 {
		return r.reader.Read(p)
	}

	startTime := time.Now()
	n, err = r.reader.Read(p)
	if n > 0 {
		expectedTime := time.Duration(float64(n) / float64(r.bytesPerSec) * float64(time.Second))
		elapsed := time.Since(startTime)
		if elapsed < expectedTime {
			time.Sleep(expectedTime - elapsed)
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

	decodedBytes, err := base64.URLEncoding.DecodeString(urlData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的URL编码",
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
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "下载文件失败",
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"message": fmt.Sprintf("源服务器返回错误状态码: %d", resp.StatusCode),
		})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, url.QueryEscape(downloadData.Filename)))
	c.Header("Content-Type", resp.Header.Get("Content-Type"))
	if resp.Header.Get("Content-Length") != "" {
		c.Header("Content-Length", resp.Header.Get("Content-Length"))
	}

	var reader io.Reader = resp.Body
	if config.SpeedLimit.Enabled {
		speed := config.SpeedLimit.NormalSpeed
		if xs {
			speed = config.SpeedLimit.LimitedSpeed
		}
		reader = &rateLimitedReader{
			reader:      resp.Body,
			bytesPerSec: speed,
		}
	}

	ip := c.ClientIP()
	counter := &CountingReader{
		Reader: reader,
		OnRead: func(bytes int64) {
			stats.UpdateUserStats(ip, bytes)
			stats.UpdateURLStats(downloadData.URL, bytes)
		},
	}

	io.Copy(c.Writer, counter)
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

	// 自定义日志中间件
	r.Use(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		if raw != "" {
			path = path + "?" + raw
		}

		log.Printf("[GIN] %s | %d | %s | %s",
			c.Request.Method,
			c.Writer.Status(),
			time.Since(start),
			path,
		)
	})

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
