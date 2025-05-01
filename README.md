# MoProxy

一个高性能的代理下载服务器，支持限速、统计和监控功能。

## 特性

- 🚀 高性能文件代理下载
- 🔐 支持密码验证和签名机制
- 📊 实时监控和统计
  - 域名访问统计
  - 用户活跃度统计
  - 实时速度监控
  - 总流量统计
- ⚡ 智能限速
  - 支持普通/限速模式
  - 可配置不同速度限制
- 💾 数据持久化
  - 使用 SQLite 存储统计数据
  - 重启不丢失历史记录
- 📱 美观的监控界面
  - 实时速度图表
  - 域名访问排名
  - 用户活跃状态

## 快速开始

### 配置文件

创建 `config.yaml` 文件：

```yaml
# 服务器配置
server:
  # 服务器监听端口
  port: 8080
  # 服务器密码
  password: "your_password"

# 限速配置
speed_limit:
  # 是否启用限速
  enabled: true
  # 普通下载速度限制 (bytes/second)
  normal_speed: 1048576  # 1MB/s
  # 限速时的下载速度 (bytes/second)
  limited_speed: 262144  # 256KB/s
```

### 运行

```bash
# 直接运行
./moproxy

# 或者从源码编译
go build
./moproxy
```

## API 文档

### 1. 测试连接

```bash
curl -X POST http://localhost:8080/api/test \
  -H "X-Proxy-Password: your_password" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://example.com/file.zip",
    "ua": "curl/7.64.1",
    "cookie": "",
    "xs": false
  }'
```

### 2. 添加下载

```bash
curl -X POST http://localhost:8080/api/add \
  -H "X-Proxy-Password: your_password" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://example.com/file.zip",
    "filename": "file.zip",
    "ua": "curl/7.64.1"
  }'
```

### 3. 获取统计信息

```bash
curl http://localhost:8080/api/stats
```

## 监控界面

访问 `http://localhost:8080` 查看实时监控界面：

- 实时速度监控
- 总体统计信息
- 活跃用户列表
- URL 访问排名

## 开发

### 依赖

- Go 1.16+
- SQLite3

### 构建

```bash
go mod download
go build
```

## 许可证

Apache License 2.0 