using System.Text;
using Newtonsoft.Json.Linq;
using PacketSniffer.Models;

namespace PacketSniffer.Parsers;

public class JsonParser : IParser
{
    public bool CanParse(byte[] payload)
    {
        if (payload == null || payload.Length == 0)
            return false;

        try
        {
            var text = Encoding.UTF8.GetString(payload).Trim();
            if (string.IsNullOrWhiteSpace(text))
                return false;

            // 检查是否以 { 或 [ 开头（JSON 格式）
            text = text.TrimStart();
            if (text.StartsWith("{") || text.StartsWith("["))
            {
                JToken.Parse(text);
                return true;
            }
        }
        catch
        {
            // 解析失败，不是有效的 JSON
        }

        return false;
    }

    public ParsedResult Parse(byte[] payload)
    {
        if (!CanParse(payload))
            throw new InvalidOperationException("Cannot parse payload as JSON");

        try
        {
            var text = Encoding.UTF8.GetString(payload).Trim();
            var json = JToken.Parse(text);

            var result = new ParsedResult
            {
                Protocol = "json"
            };

            // 解析所有一级字段
            if (json is JObject obj)
            {
                foreach (var prop in obj.Properties())
                {
                    result.Fields[prop.Name] = prop.Value?.ToString() ?? string.Empty;
                }
            }
            else if (json is JArray array)
            {
                result.Fields["array_length"] = array.Count.ToString();
                result.Fields["array_content"] = array.ToString();
            }
            else
            {
                result.Fields["value"] = json.ToString();
            }

            return result;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse JSON: {ex.Message}", ex);
        }
    }
}

