using PacketSniffer.Messaging;
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

    public RabbitProducer Producer { get; set; } = new();

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
            // 只关注 HTTP Request
            if (!string.Equals(result.Protocol, "http", StringComparison.OrdinalIgnoreCase) ||
                !result.Fields.TryGetValue("http_type", out var httpType) ||
                !httpType.Equals("request", StringComparison.OrdinalIgnoreCase) ||
                !result.Fields.TryGetValue("request_line", out var requestLine))
            {
                return;
            }

            // 解析请求行：METHOD SP PATH SP HTTP/...
                var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var method = parts.Length >= 1 ? parts[0] : string.Empty;
                var path = parts.Length >= 2 ? parts[1] : string.Empty;

            // 可选：按路径过滤（如果配置了 HttpPathFilters）
            if (HttpPathFilters.Count > 0)
            {
                var match = HttpPathFilters.Any(filter =>
                    !string.IsNullOrWhiteSpace(filter) &&
                    path.Contains(filter, StringComparison.OrdinalIgnoreCase));

                if (!match)
                {
                    // 不匹配任何关注路径，则直接丢弃该请求（对应响应可能仍然会被抓到）
                    return;
                }
            }

            // 记录时间戳和基本信息
            result.Timestamp = DateTime.Now;
            result.Fields["source_port"] = sourcePort.ToString();
            result.Fields["destination_port"] = destinationPort.ToString();
            result.Fields["transport_protocol"] = protocol;
            result.Fields["http_path"] = path;

            // 只打印请求时间 + 方法 + 路径
            Console.WriteLine("======================================================================================================================");
            Console.WriteLine($"[{result.Timestamp:yyyy-MM-dd HH:mm:ss.fff}] {method} {path}  (src:{sourcePort} -> dst:{destinationPort})");

            // 暂不做后续业务处理；后续有需求时可以在这里调用 HandleBusinessLogic(result)
            Producer.Send(method + "\t" + path);
        }
    }

    public void HandleBusinessLogic(ParsedResult result)
    {
        // 如果 Fields 包含 "userId"，打印 "检测到用户操作 userId=xxx"
        if (result.Fields.ContainsKey("result"))
        {
            var userId = result.Fields["result"];
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

