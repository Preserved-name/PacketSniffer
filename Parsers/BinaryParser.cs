using System.Text;
using PacketSniffer.Models;

namespace PacketSniffer.Parsers;

public class BinaryParser : IParser
{
    public bool CanParse(byte[] payload)
    {
        // 兜底解析器，永远返回 true
        return true;
    }

    public ParsedResult Parse(byte[] payload)
    {
        var result = new ParsedResult
        {
            Protocol = "binary"
        };

        if (payload != null && payload.Length > 0)
        {
            // TODO: 在此扩展自定义协议解析
            var hexString = BitConverter.ToString(payload).Replace("-", " ");
            result.Fields["hex"] = hexString;
        }
        else
        {
            result.Fields["hex"] = string.Empty;
        }

        return result;
    }
}

