package main

import (
	"fmt"
	"log"
)

// 这是一个使用SDK的示例
// 注意：这个文件仅作为示例，不会被编译到主程序中

func exampleUsage() {
	// 1. 创建SDK实例
	sdk := NewProxySDK(
		"https://your-proxy-server.com", // 服务器地址
		"your-password",                  // 服务器密码
	)

	// 2. 方式一：使用单独的参数生成下载链接
	downloadURL, err := sdk.GenerateDownloadURL(
		"https://example.com/file.zip",           // 目标下载URL
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", // User-Agent（可选）
		"myfile.zip",                             // 文件名（可选，为空时服务器会自动获取）
	)
	if err != nil {
		log.Fatalf("生成下载链接失败: %v", err)
	}
	fmt.Printf("下载链接: %s\n", downloadURL)

	// 3. 方式二：使用DownloadInfo结构生成下载链接
	info := DownloadInfo{
		URL:      "https://example.com/file.zip",
		UA:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Filename: "myfile.zip", // 可选，为空时服务器会自动获取
	}
	downloadURL2, err := sdk.GenerateDownloadURLWithInfo(info)
	if err != nil {
		log.Fatalf("生成下载链接失败: %v", err)
	}
	fmt.Printf("下载链接: %s\n", downloadURL2)

	// 4. 不指定文件名，让服务器自动获取
	downloadURL3, err := sdk.GenerateDownloadURL(
		"https://example.com/file.zip",
		"", // 使用默认User-Agent
		"", // 不指定文件名，服务器会自动从响应头获取
	)
	if err != nil {
		log.Fatalf("生成下载链接失败: %v", err)
	}
	fmt.Printf("下载链接: %s\n", downloadURL3)
}

