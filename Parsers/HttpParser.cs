using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using PacketSniffer.Models;

namespace PacketSniffer.Parsers;

public class HttpParser : IParser
{
    private static readonly Regex HttpMethodRegex = new(@"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+", RegexOptions.IgnoreCase);
    private static readonly Regex HttpVersionRegex = new(@"^HTTP/\d\.\d", RegexOptions.IgnoreCase);

    public bool CanParse(byte[] payload)
    {
        if (payload == null || payload.Length == 0)
            return false;

        try
        {
            var text = Encoding.UTF8.GetString(payload);
            if (string.IsNullOrWhiteSpace(text))
                return false;

            // 检查是否以 HTTP 方法或 HTTP/1.x 开头
            text = text.TrimStart();
            return HttpMethodRegex.IsMatch(text) || HttpVersionRegex.IsMatch(text);
        }
        catch
        {
            return false;
        }
    }

    public ParsedResult Parse(byte[] payload)
    {
        if (!CanParse(payload))
            throw new InvalidOperationException("Cannot parse payload as HTTP");

        try
        {
            var text = Encoding.UTF8.GetString(payload);
            var result = new ParsedResult
            {
                Protocol = "http"
            };

            // 分离 Header 和 Body
            var headerBodySplit = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headerBodySplit == -1)
                headerBodySplit = text.IndexOf("\n\n", StringComparison.Ordinal);

            string headers = headerBodySplit > 0 ? text.Substring(0, headerBodySplit) : text;
            string body = headerBodySplit > 0 && headerBodySplit + 4 < text.Length 
                ? text.Substring(headerBodySplit + 4) 
                : string.Empty;

            // 解析 HTTP Headers
            var headerLines = headers.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            
            // 第一行是请求行或状态行
            if (headerLines.Length > 0)
            {
                var firstLine = headerLines[0];
                result.Fields["request_line"] = firstLine;

                // 判断是请求还是响应
                if (firstLine.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                {
                    result.Fields["http_type"] = "response";
                }
                else
                {
                    result.Fields["http_type"] = "request";
                }
            }

            // 解析其他 headers
            for (int i = 1; i < headerLines.Length; i++)
            {
                var line = headerLines[i];
                var colonIndex = line.IndexOf(':');
                if (colonIndex > 0)
                {
                    var key = line.Substring(0, colonIndex).Trim();
                    var value = line.Substring(colonIndex + 1).Trim();
                    result.Fields[$"header_{key}"] = value;
                }
            }

            // 如果 Body 存在，先保留原始内容（截断避免过长）
            if (!string.IsNullOrWhiteSpace(body))
            {
                var bodyTrimmed = body.Trim();
                const int maxBodyLen = 4000;
                var rawBodyForLog = bodyTrimmed.Length > maxBodyLen
                    ? bodyTrimmed[..maxBodyLen] + $" ... (len={bodyTrimmed.Length}, truncated)"
                    : bodyTrimmed;

                result.Fields["body_raw"] = rawBodyForLog;

                // 如果 Body 是 JSON，解析 JSON 字段
                try
                {
                    if (bodyTrimmed.StartsWith("{") || bodyTrimmed.StartsWith("["))
                    {
                        var json = JToken.Parse(bodyTrimmed);
                        if (json is JObject obj)
                        {
                            foreach (var prop in obj.Properties())
                            {
                                result.Fields[prop.Name] = prop.Value?.ToString() ?? string.Empty;
                            }
                        }
                        else
                        {
                            // 数组等非对象情况也保留整体
                            result.Fields["body_json"] = bodyTrimmed;
                        }
                    }
                    else
                    {
                        // 非 JSON，直接作为文本保存
                        result.Fields["body_text"] = bodyTrimmed;
                    }
                }
                catch
                {
                    // JSON 解析失败，按纯文本保存
                    result.Fields["body_text"] = bodyTrimmed;
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse HTTP: {ex.Message}", ex);
        }
    }
}

