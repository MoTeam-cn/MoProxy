# PikPak 下载接口文档

## 接口说明
该接口用于获取 PikPak 文件的下载链接，支持直接下载链接和媒体文件链接。

## 接口信息
- **接口路径**：`/api/pikpak/down`
- **请求方法**：POST
- **需要认证**：是

## 认证方式
在请求头中添加：
```http
X-Proxy-Password: your_proxy_password
```

## 请求参数
### 请求头
```http
Content-Type: application/json
X-Proxy-Password: your_proxy_password
```

### 请求体
```json
{
    "file_id": "PikPak文件ID",
    "access_token": "PikPak访问令牌",
    "user_agent": "客户端用户代理",
    "device_id": "设备ID",
    "captcha_token": "验证码令牌（可选）"
}
```

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| file_id | string | 是 | PikPak 文件的唯一标识符 |
| access_token | string | 是 | PikPak 的访问令牌 |
| user_agent | string | 是 | 客户端的用户代理标识 |
| device_id | string | 是 | 设备的唯一标识符 |
| captcha_token | string | 否 | 验证码令牌，如果需要验证码时必填 |

## 响应参数
### 成功响应
```json
{
    "success": true,
    "data": {
        "web_content_link": "直接下载链接",
        "medias": [
            {
                "media_id": "媒体ID",
                "media_name": "媒体名称",
                "video": {
                    "height": 1080,
                    "width": 1920,
                    "duration": 3600,
                    "bit_rate": 1500000,
                    "frame_rate": 30,
                    "video_codec": "h264",
                    "audio_codec": "aac",
                    "video_type": "mp4"
                },
                "link": {
                    "url": "媒体文件下载链接",
                    "token": "下载令牌",
                    "expire": "过期时间"
                },
                "need_more_quota": false,
                "vip_types": [],
                "redirect_link": "重定向链接",
                "icon_link": "图标链接",
                "is_default": true,
                "priority": 1,
                "is_origin": true,
                "resolution_name": "1080P",
                "is_visible": true,
                "category": "video"
            }
        ]
    }
}
```

### 错误响应
```json
{
    "success": false,
    "message": "错误信息"
}
```

## 错误码说明
| HTTP状态码 | 说明 |
|------------|------|
| 400 | 请求参数错误 |
| 401 | 认证失败（代理密码错误） |
| 500 | 服务器内部错误 |
| 502 | PikPak API 请求失败 |

## 调用示例
### cURL
```bash
curl -X POST 'http://your-server:port/api/pikpak/down' \
  -H 'Content-Type: application/json' \
  -H 'X-Proxy-Password: your_proxy_password' \
  -d '{
    "file_id": "your_file_id",
    "access_token": "your_access_token",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "device_id": "your_device_id",
    "captcha_token": "optional_captcha_token"
  }'
```

### JavaScript
```javascript
const response = await fetch('http://your-server:port/api/pikpak/down', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Proxy-Password': 'your_proxy_password'
  },
  body: JSON.stringify({
    file_id: 'your_file_id',
    access_token: 'your_access_token',
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    device_id: 'your_device_id',
    captcha_token: 'optional_captcha_token'
  })
});

const data = await response.json();
console.log(data);
```

### Python
```python
import requests

url = 'http://your-server:port/api/pikpak/down'
headers = {
    'Content-Type': 'application/json',
    'X-Proxy-Password': 'your_proxy_password'
}
data = {
    'file_id': 'your_file_id',
    'access_token': 'your_access_token',
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'device_id': 'your_device_id',
    'captcha_token': 'optional_captcha_token'
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

## 注意事项
1. 所有请求必须包含有效的 `X-Proxy-Password` 请求头
2. `access_token` 需要通过 PikPak 的登录接口获取
3. 返回的下载链接可能有时效性，请及时使用
4. 如果遇到验证码要求，需要提供有效的 `captcha_token`
5. 建议在服务器端进行速率限制，避免过于频繁的 API 调用
