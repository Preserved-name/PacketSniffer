using System.Text.Json;

namespace PacketSniffer.Config;

/// <summary>
/// 程序运行时的可配置项，从根目录的 config.json 读取。
/// </summary>
public class AppSettings
{
    /// <summary>
    /// 网卡筛选关键字（从 Name/Description 中模糊匹配）。
    /// 例如：\"Intel\", \"Realtek\", \"Npcap Loopback\" 等。
    /// 为空则使用自动选择策略（物理网卡优先，其次 Loopback）。
    /// </summary>
    public string? DeviceKeyword { get; set; }

    /// <summary>
    /// 需要监听的端口列表，null 或空表示监听所有端口。
    /// 例如：[80,443,5000]。
    /// </summary>
    public List<int>? Ports { get; set; }

    /// <summary>
    /// 是否按照源端口进行过滤（默认 true）。
    /// </summary>
    public bool FilterSourcePort { get; set; } = true;

    /// <summary>
    /// 是否按照目标端口进行过滤（默认 true）。
    /// </summary>
    public bool FilterDestinationPort { get; set; } = true;

    /// <summary>
    /// HTTP 路径过滤列表；只对 HTTP Request 生效。
    /// PATH 中只要包含任意一个字符串，就会被打印；为空表示不过滤。
    /// 例如：[\"/api/\", \"/WeatherForecast\"]。
    /// </summary>
    public List<string>? HttpPathFilters { get; set; }
}

public static class AppConfig
{
    private const string ConfigFileName = "config.json";

    public static AppSettings Load()
    {
        try
        {
            // 始终从程序所在目录读取 config.json
            var baseDir = AppContext.BaseDirectory;
            var configPath = Path.Combine(baseDir, ConfigFileName);

            if (!File.Exists(configPath))
            {
                Console.WriteLine($"配置文件 {configPath} 不存在，使用默认配置");
                return new AppSettings();
            }

            var json = File.ReadAllText(configPath);
            var settings = JsonSerializer.Deserialize<AppSettings>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (settings == null)
            {
                Console.WriteLine($"配置文件 {configPath} 反序列化结果为 null，使用默认配置");
                return new AppSettings();
            }

            Console.WriteLine($"已加载配置文件: {configPath}");
            return settings;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"读取配置文件失败，将使用默认配置。错误: {ex.Message}");
            return new AppSettings();
        }
    }
}


