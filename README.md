# PacketSniffer - 实时网络抓包与协议解析工具

一个基于 C# 开发的实时网络抓包工具，支持自动协议识别、解析和业务逻辑分发。

## 功能特性

- 🔍 **实时抓包**：使用 SharpPcap 进行网络数据包捕获
- 🔄 **自动协议识别**：支持 JSON、HTTP、二进制协议自动识别
- 📊 **智能解析**：自动提取协议字段和内容
- 🎯 **业务分发**：支持自定义业务逻辑处理
- 🛡️ **扩展性强**：易于添加新的协议解析器

## 项目结构

```
PacketSniffer/
├── PacketSniffer.csproj      # 项目配置文件
├── Program.cs                 # 程序入口
├── Core/
│   ├── Sniffer.cs            # 抓包核心模块
│   └── PacketRouter.cs       # 数据包路由分发器
├── Parsers/
│   ├── IParser.cs            # 解析器接口
│   ├── JsonParser.cs         # JSON 协议解析器
│   ├── HttpParser.cs         # HTTP 协议解析器
│   └── BinaryParser.cs       # 二进制协议解析器（兜底）
└── Models/
    └── ParsedResult.cs       # 解析结果数据模型
```

## 环境要求

- .NET 6.0 或更高版本
- Windows 操作系统（需要管理员权限运行）
- 已安装的网络适配器

## 安装步骤

### 1. 克隆或下载项目

```bash
cd "D:\C# Project\zhuabao"
```

### 2. 恢复 NuGet 依赖

```bash
dotnet restore
```

### 3. 构建项目

```bash
dotnet build
```

## 使用方法

### 基本运行

**重要：必须以管理员权限运行！**

```bash
# 方式1：监听所有端口（默认）
dotnet run

# 方式2：监听指定端口（例如：80, 443, 8080）
dotnet run 80 443 8080

# 方式3：先构建后运行
dotnet build
dotnet bin/Debug/net6.0/PacketSniffer.exe 80 443
```

### 端口配置

程序支持通过命令行参数指定要监听的端口：

- **不指定参数**：监听所有端口（默认行为）
- **指定端口**：只监听指定的端口（源端口或目标端口匹配即可）

**示例：**
```bash
# 监听 HTTP 和 HTTPS 流量
dotnet run 80 443

# 监听多个端口
dotnet run 80 443 8080 3000 9000

# 监听所有端口
dotnet run
```

**端口过滤逻辑：**
- 如果数据包的**源端口**或**目标端口**在允许列表中，就会被处理
- 支持同时监听多个端口
- 端口范围：1-65535

### 运行流程

1. 程序启动后会自动选择第一块可用的网络适配器
2. 开启混杂模式（Promiscuous Mode）进行抓包
3. 实时捕获 TCP/UDP 数据包的 payload
4. 自动识别协议类型（JSON → HTTP → Binary）
5. 解析并提取字段信息
6. 触发业务逻辑处理
7. 在控制台输出解析结果

### 停止程序

按 `Ctrl+C` 优雅退出，程序会自动停止抓包并清理资源。

## 协议解析说明

### JSON 协议解析

- **识别方式**：检查 payload 是否以 `{` 或 `[` 开头
- **解析内容**：提取所有一级字段的键值对
- **输出格式**：`Protocol=json, Fields={key1=value1, key2=value2, ...}`

### HTTP 协议解析

- **识别方式**：检查是否以 HTTP 方法（GET/POST等）或 `HTTP/1.x` 开头
- **解析内容**：
  - 解析 HTTP Headers（所有 header 字段）
  - 解析 Request Line 或 Status Line
  - 如果 Body 是 JSON 格式，自动解析 JSON 字段
- **输出格式**：`Protocol=http, Fields={request_line=..., header_Content-Type=..., ...}`

### 二进制协议解析

- **识别方式**：作为兜底解析器，所有无法识别的协议都会使用此解析器
- **解析内容**：将 payload 转换为十六进制字符串
- **输出格式**：`Protocol=binary, Fields={hex=AA BB CC DD ...}`
- **扩展提示**：可在 `BinaryParser.cs` 中添加自定义协议解析逻辑

## 业务逻辑处理

程序会自动检测以下业务场景：

### 1. 用户操作检测

如果解析结果中包含 `userId` 字段：
```
>>> 检测到用户操作 userId=12345
```

### 2. 上传操作检测

如果解析结果中包含 `action=upload` 字段：
```
>>> 触发上传业务逻辑
```

### 3. HTTP 认证检测

如果是 HTTP 协议且包含 `Authorization` Header：
```
>>> HTTP Authorization Token: Bearer xxxxxx
```

## 自定义扩展

### 添加新的协议解析器

1. 实现 `IParser` 接口：

```csharp
public class CustomParser : IParser
{
    public bool CanParse(byte[] payload)
    {
        // 判断逻辑
        return false;
    }

    public ParsedResult Parse(byte[] payload)
    {
        // 解析逻辑
        return new ParsedResult { ... };
    }
}
```

2. 在 `Program.cs` 中注册：

```csharp
router.RegisterParser(new CustomParser());
```

### 扩展业务逻辑

在 `PacketRouter.cs` 的 `HandleBusinessLogic()` 方法中添加自定义逻辑：

```csharp
private void HandleBusinessLogic(ParsedResult result)
{
    // 添加你的业务逻辑
    if (result.Fields.ContainsKey("yourKey"))
    {
        // 处理逻辑
    }
}
```

## 输出示例

### 监听所有端口

```
=== Packet Sniffer Started ===
端口过滤: 已禁用（监听所有端口）
提示: 使用命令行参数指定端口，例如: dotnet run 80 443 8080
Using device: \Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
Packet capture started. Press Ctrl+C to stop.
Press Ctrl+C to stop...

=== Parsed Packet ===
[TCP] 54321 -> 80
[http] request_line=GET /api/users HTTP/1.1, header_Authorization=Bearer token123, source_port=54321, destination_port=80, transport_protocol=TCP
====================

>>> HTTP Authorization Token: Bearer token123
```

### 监听指定端口

```
=== Packet Sniffer Started ===
端口过滤: 已启用，监听端口: 80, 443, 8080
过滤模式: 源端口=True, 目标端口=True
Using device: \Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
Packet capture started. Press Ctrl+C to stop.

=== Parsed Packet ===
[TCP] 54321 -> 80
[json] userId=12345, action=upload, filename=test.jpg, source_port=54321, destination_port=80, transport_protocol=TCP
====================

>>> 检测到用户操作 userId=12345
>>> 触发上传业务逻辑
```

## 端口配置说明

### 配置方式

1. **命令行参数**（推荐）：
   ```bash
   dotnet run 80 443 8080
   ```

2. **代码中配置**（修改 `Program.cs`）：
   ```csharp
   sniffer.AllowedPorts = new HashSet<int> { 80, 443, 8080 };
   sniffer.FilterBySourcePort = true;      // 是否过滤源端口
   sniffer.FilterByDestinationPort = true; // 是否过滤目标端口
   ```

### 过滤规则

- **源端口过滤**：如果数据包的源端口在允许列表中，会被处理
- **目标端口过滤**：如果数据包的目标端口在允许列表中，会被处理
- **同时匹配**：只要源端口或目标端口任一匹配，就会被处理
- **不过滤**：如果 `AllowedPorts = null`，则监听所有端口

### 常见端口

- **80** - HTTP
- **443** - HTTPS
- **8080** - HTTP 代理/备用 HTTP
- **3000** - 开发服务器常用端口
- **3306** - MySQL
- **5432** - PostgreSQL
- **6379** - Redis

## 注意事项

1. **管理员权限**：抓包功能需要管理员权限，否则无法打开网络适配器
2. **防火墙**：某些防火墙可能会阻止抓包操作
3. **性能影响**：大量网络流量可能会影响程序性能，建议使用端口过滤减少处理量
4. **隐私安全**：请确保在合法合规的环境中使用，不要抓取他人隐私数据
5. **端口过滤**：使用端口过滤可以显著减少处理的数据包数量，提高性能

## 故障排除

### 问题1：找不到网络设备

**错误信息**：`No network devices found`

**解决方案**：
- 确保已安装网络适配器驱动
- 检查是否有可用的网络连接
- 尝试以管理员权限运行

### 问题2：无法打开设备

**错误信息**：`Failed to open device`

**解决方案**：
- 确保以管理员权限运行
- 检查是否有其他程序占用网络适配器
- 尝试重启程序

### 问题3：解析失败

**现象**：某些数据包无法解析

**说明**：这是正常现象，无法识别的协议会使用 BinaryParser 输出十六进制格式

## 技术栈

- **.NET 6.0** - 开发框架
- **SharpPcap 6.2.5** - 网络抓包库
- **PacketDotNet 1.4.7** - 数据包解析库
- **Newtonsoft.Json 13.0.3** - JSON 解析库

## 许可证

本项目仅供学习和研究使用。

## 更新日志

### v1.0.0 (2024)
- ✅ 实现实时网络抓包功能
- ✅ 支持 JSON/HTTP/二进制协议自动识别
- ✅ 实现业务逻辑分发机制
- ✅ 支持优雅退出（Ctrl+C）

## 联系方式

如有问题或建议，请提交 Issue 或 Pull Request。

---

**⚠️ 免责声明**：本工具仅供学习和合法用途使用，使用者需自行承担使用本工具所产生的法律责任。

