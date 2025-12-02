using PacketSniffer.Models;
using PacketSniffer.Parsers;

namespace PacketSniffer.Core;

public class PacketRouter
{
    private readonly List<IParser> _parsers = new();

    /// <summary>
    /// HTTP 路径过滤列表（只对 HTTP 请求生效）
    /// 例如：/api/user, /api/order
    /// 为空时不过滤，所有路径都打印
    /// </summary>
    public List<string> HttpPathFilters { get; } = new();

    public void RegisterParser(IParser parser)
    {
        if (parser == null)
            throw new ArgumentNullException(nameof(parser));

        _parsers.Add(parser);
    }

    public void Route(byte[] payload, int sourcePort, int destinationPort, string protocol)
    {
        if (payload == null || payload.Length == 0)
            return;

        ParsedResult? result = null;

        // 按顺序尝试解析器：JsonParser → HttpParser → BinaryParser
        foreach (var parser in _parsers)
        {
            try
            {
                if (parser.CanParse(payload))
                {
                    result = parser.Parse(payload);
                    break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Parser {parser.GetType().Name} failed: {ex.Message}");
                continue;
            }
        }

        // 如果所有解析器都失败，使用 BinaryParser 作为兜底
        if (result == null && _parsers.Count > 0)
        {
            var binaryParser = _parsers.LastOrDefault(p => p is BinaryParser);
            if (binaryParser != null)
            {
                try
                {
                    result = binaryParser.Parse(payload);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"BinaryParser failed: {ex.Message}");
                }
            }
        }

        if (result != null)
        {
            // 记录时间戳
            result.Timestamp = DateTime.Now;

            // 添加端口和传输协议信息
            result.Fields["source_port"] = sourcePort.ToString();
            result.Fields["destination_port"] = destinationPort.ToString();
            result.Fields["transport_protocol"] = protocol;

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
                    // 不匹配任何关注路径，则直接丢弃该请求（对应响应可能仍然会被抓到）
                    return;
                }

                // 记录解析后的 path 便于查看
                result.Fields["http_path"] = path;
            }

            // HTTP 请求/响应方向提示
            string httpInfo = string.Empty;
            if (result.Protocol == "http" && result.Fields.TryGetValue("http_type", out var httpType2))
            {
                httpInfo = httpType2.Equals("response", StringComparison.OrdinalIgnoreCase)
                    ? "HTTP RESPONSE"
                    : "HTTP REQUEST";
            }

            // 打印解析结果
            Console.WriteLine("\n=== Parsed Packet ===");
            Console.WriteLine($"Time: {result.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
            Console.WriteLine($"Direction: [{protocol}] {sourcePort} -> {destinationPort} {httpInfo}");
            Console.WriteLine(result.ToString());
            Console.WriteLine("====================\n");

            // 调用业务逻辑
            HandleBusinessLogic(result);
        }
    }

    private void HandleBusinessLogic(ParsedResult result)
    {
        // 如果 Fields 包含 "userId"，打印 "检测到用户操作 userId=xxx"
        if (result.Fields.ContainsKey("userId"))
        {
            var userId = result.Fields["userId"];
            Console.WriteLine($">>> 检测到用户操作 userId={userId}");
        }

        // 如果 action = "upload"，打印 "触发上传业务逻辑"
        if (result.Fields.ContainsKey("action") && 
            result.Fields["action"].Equals("upload", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($">>> 触发上传业务逻辑");
        }

        // 如果是 HTTP 协议，且包含 Authorization，则打印 Token
        if (result.Protocol == "http")
        {
            var authKey = result.Fields.Keys.FirstOrDefault(k => 
                k.Equals("header_Authorization", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("Authorization", StringComparison.OrdinalIgnoreCase));

            if (authKey != null)
            {
                var token = result.Fields[authKey];
                Console.WriteLine($">>> HTTP Authorization Token: {token}");
            }
        }
    }
}

