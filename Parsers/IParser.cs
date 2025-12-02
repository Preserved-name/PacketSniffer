using PacketSniffer.Models;

namespace PacketSniffer.Parsers;

public interface IParser
{
    bool CanParse(byte[] payload);
    ParsedResult Parse(byte[] payload);
}

