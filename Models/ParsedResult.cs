using System.Text;

namespace PacketSniffer.Models;

public class ParsedResult
{
    /// <summary>
    /// 协议名称（如 json/http/binary）
    /// </summary>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>
    /// 解析出的字段
    /// </summary>
    public Dictionary<string, string> Fields { get; set; } = new();

    /// <summary>
    /// 捕获/解析时间
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.Now;

    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] Protocol={Protocol}");

        foreach (var kvp in Fields)
        {
            var value = kvp.Value ?? string.Empty;

            // 对特别长的内容做截断，避免刷屏
            const int maxLen = 2000;
            if (value.Length > maxLen)
            {
                value = value[..maxLen] + $" ... (len={kvp.Value?.Length}, truncated)";
            }

            sb.AppendLine($"  {kvp.Key}: {value}");
        }

        return sb.ToString();
    }
}

