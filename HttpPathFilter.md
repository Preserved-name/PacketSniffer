## HTTP 路径过滤配置说明

本项目支持 **按 URL 路径过滤 HTTP 请求**，只打印你关心的接口请求/响应，减少无关噪声。

### 一、过滤逻辑概览

- **生效范围**：仅对 **HTTP 请求** 生效（`GET /xxx HTTP/1.1` 这一行）
- **匹配规则**：如果请求路径中 **包含任意一个配置的片段**，则认为命中；否则直接丢弃该 HTTP 请求日志
- **响应处理**：当前版本只对请求做路径过滤，响应是否打印取决于是否能被当前抓包捕获，但不会再按路径过滤

示例：

- 请求行：`GET /api/user/123 HTTP/1.1`
- 配置：`/api/user`
- 结果：该请求会被打印，并在字段中额外看到 `http_path: /api/user/123`

---

### 二、配置入口位置

#### 1. 在 `PacketRouter` 中的过滤字段

文件：`Core/PacketRouter.cs`

字段定义位置：

```csharp
public class PacketRouter
{
    private readonly List<IParser> _parsers = new();

    /// <summary>
    /// HTTP 路径过滤列表（只对 HTTP 请求生效）
    /// 例如：/api/user, /api/order
    /// 为空时不过滤，所有路径都打印
    /// </summary>
    public List<string> HttpPathFilters { get; } = new();

    // ...
}
```

你不需要直接改这里，这里只是存放配置的地方。

#### 2. 实际配置路径的地方（你要改的地方）

文件：`Program.cs`  
方法：`ConfigureHttpPathFilter(PacketRouter router)`

位置大致如下（在文件底部附近）：

```csharp
/// <summary>
/// 配置 HTTP 路径过滤
/// 只对 HTTP 请求生效：request_line 里的 PATH 包含任意一个配置片段才会打印
/// 默认不过滤（列表为空），只需在这里按需要添加路径关键字
/// </summary>
private static void ConfigureHttpPathFilter(PacketRouter router)
{
    // 示例：只关注 /api/user 和 /api/order 相关的 HTTP 请求
    // router.HttpPathFilters.Add("/api/user");
    // router.HttpPathFilters.Add("/api/order");

    // 默认：不过滤任何路径
    // 如果你想只看某个接口，比如 /WeatherForecast，可以这样写：
    // router.HttpPathFilters.Add("/WeatherForecast");
}
```

**你要做的就是在这里取消注释 / 添加路径片段。**

---

### 三、具体配置示例

#### 1. 只看某个接口（例如 `/WeatherForecast`）

修改 `Program.cs` 中的 `ConfigureHttpPathFilter`：

```csharp
private static void ConfigureHttpPathFilter(PacketRouter router)
{
    router.HttpPathFilters.Add("/WeatherForecast");
}
```

效果：

- 只有请求行中 **路径包含 `/WeatherForecast`** 的 HTTP 请求会被打印
- 例如：`GET /WeatherForecast HTTP/1.1`、`GET /WeatherForecast?x=1` 都会被打印

#### 2. 只看后台 API 前缀 `/api/` 相关请求

```csharp
private static void ConfigureHttpPathFilter(PacketRouter router)
{
    router.HttpPathFilters.Add("/api/");
}
```

效果：

- 所有 `GET /api/...`、`POST /api/...` 请求会被打印
- 其他路径（如 `/favicon.ico`、`/swagger`）将被丢弃

#### 3. 关注多个接口

```csharp
private static void ConfigureHttpPathFilter(PacketRouter router)
{
    router.HttpPathFilters.Add("/api/user");
    router.HttpPathFilters.Add("/api/order");
    router.HttpPathFilters.Add("/health");
}
```

效果：

- 请求路径中只要包含 `/api/user` 或 `/api/order` 或 `/health`，就会被打印

#### 4. 关闭路径过滤（恢复打印所有 HTTP 请求）

```csharp
private static void ConfigureHttpPathFilter(PacketRouter router)
{
    // 不添加任何路径，列表为空 => 不过滤
}
```

---

### 四、过滤在路由中的生效位置（供你理解，不一定要改）

文件：`Core/PacketRouter.cs`  
方法：`Route(byte[] payload, int sourcePort, int destinationPort, string protocol)`

关键逻辑（简化版）：

```csharp
// HTTP 请求路径过滤（只过滤请求，不过滤响应）
if (result.Protocol == "http" &&
    HttpPathFilters.Count > 0 &&
    result.Fields.TryGetValue("http_type", out var httpType) &&
    httpType.Equals("request", StringComparison.OrdinalIgnoreCase) &&
    result.Fields.TryGetValue("request_line", out var requestLine))
{
    // 解析请求路径：METHOD SP PATH SP HTTP/...
    var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    var path = parts.Length >= 2 ? parts[1] : string.Empty;

    var match = HttpPathFilters.Any(filter =>
        !string.IsNullOrWhiteSpace(filter) &&
        path.Contains(filter, StringComparison.OrdinalIgnoreCase));

    if (!match)
    {
        // 不匹配任何关注路径，则直接丢弃该请求
        return;
    }

    // 记录解析后的 path 便于查看
    result.Fields["http_path"] = path;
}
```


