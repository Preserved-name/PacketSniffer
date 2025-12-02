using System.Text;
using PacketSniffer.Models;

namespace PacketSniffer.Core;

/// <summary>
/// 数据包信息打印器
/// </summary>
public class PacketPrinter
{
    private readonly bool _showPayload;
    private readonly int _maxPayloadBytes;
    private readonly bool _showHex;
    private readonly bool _showText;

    public PacketPrinter(bool showPayload = true, int maxPayloadBytes = 256, bool showHex = true, bool showText = true)
    {
        _showPayload = showPayload;
        _maxPayloadBytes = maxPayloadBytes;
        _showHex = showHex;
        _showText = showText;
    }

    /// <summary>
    /// 打印完整的数据包信息
    /// </summary>
    public void PrintPacket(PacketInfo packet)
    {
        Console.WriteLine("\n" + new string('=', 80));
        Console.WriteLine($"数据包捕获时间: {packet.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
        Console.WriteLine(new string('-', 80));

        // 基本信息
        Console.WriteLine($"数据包长度: {packet.Length} 字节");
        Console.WriteLine($"链路层类型: {packet.LinkLayerType}");

        // MAC 地址
        if (!string.IsNullOrEmpty(packet.SourceMac))
            Console.WriteLine($"源 MAC 地址: {packet.SourceMac}");
        if (!string.IsNullOrEmpty(packet.DestinationMac))
            Console.WriteLine($"目标 MAC 地址: {packet.DestinationMac}");

        // 网络层信息
        if (!string.IsNullOrEmpty(packet.NetworkProtocol))
        {
            Console.WriteLine($"\n网络层协议: {packet.NetworkProtocol}");
            if (packet.IpVersion.HasValue)
                Console.WriteLine($"IP 版本: IPv{packet.IpVersion}");
            if (!string.IsNullOrEmpty(packet.SourceIp))
                Console.WriteLine($"源 IP 地址: {packet.SourceIp}");
            if (!string.IsNullOrEmpty(packet.DestinationIp))
                Console.WriteLine($"目标 IP 地址: {packet.DestinationIp}");
            if (packet.IpHeaderLength.HasValue)
                Console.WriteLine($"IP 头部长度: {packet.IpHeaderLength} 字节");
            if (packet.Ttl.HasValue)
                Console.WriteLine($"TTL: {packet.Ttl}");
        }

        // 传输层信息
        if (!string.IsNullOrEmpty(packet.TransportProtocol))
        {
            Console.WriteLine($"\n传输层协议: {packet.TransportProtocol}");

            if (packet.TransportProtocol == "TCP")
            {
                if (packet.SourcePort.HasValue)
                    Console.WriteLine($"源端口: {packet.SourcePort}");
                if (packet.DestinationPort.HasValue)
                    Console.WriteLine($"目标端口: {packet.DestinationPort}");
                if (!string.IsNullOrEmpty(packet.TcpFlags))
                    Console.WriteLine($"TCP 标志: {packet.TcpFlags}");
                if (packet.TcpSequenceNumber.HasValue)
                    Console.WriteLine($"序列号: {packet.TcpSequenceNumber}");
                if (packet.TcpAcknowledgmentNumber.HasValue)
                    Console.WriteLine($"确认号: {packet.TcpAcknowledgmentNumber}");
            }
            else if (packet.TransportProtocol == "UDP")
            {
                if (packet.SourcePort.HasValue)
                    Console.WriteLine($"源端口: {packet.SourcePort}");
                if (packet.DestinationPort.HasValue)
                    Console.WriteLine($"目标端口: {packet.DestinationPort}");
                if (packet.UdpLength.HasValue)
                    Console.WriteLine($"UDP 长度: {packet.UdpLength} 字节");
            }
            else if (packet.TransportProtocol == "ICMP")
            {
                Console.WriteLine("ICMP 协议包");
            }
        }

        // Payload 信息
        if (_showPayload && packet.Payload != null && packet.PayloadLength > 0)
        {
            Console.WriteLine($"\nPayload 长度: {packet.PayloadLength} 字节");

            var payloadToShow = packet.Payload;
            var isTruncated = false;

            if (packet.PayloadLength > _maxPayloadBytes)
            {
                payloadToShow = packet.Payload.Take(_maxPayloadBytes).ToArray();
                isTruncated = true;
            }

            // 显示十六进制
            if (_showHex)
            {
                Console.WriteLine("\nPayload (十六进制):");
                PrintHexDump(payloadToShow);
                if (isTruncated)
                    Console.WriteLine($"... (已截断，仅显示前 {_maxPayloadBytes} 字节)");
            }

            // 显示文本
            if (_showText)
            {
                Console.WriteLine("\nPayload (文本):");
                var text = Encoding.UTF8.GetString(payloadToShow);
                // 只显示可打印字符
                var printableText = new string(text.Where(c => char.IsControl(c) ? c == '\n' || c == '\r' || c == '\t' : char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsSymbol(c) || char.IsWhiteSpace(c)).ToArray());
                Console.WriteLine(printableText);
                if (isTruncated)
                    Console.WriteLine($"... (已截断)");
            }
        }
        else if (packet.PayloadLength == 0)
        {
            Console.WriteLine("\nPayload: 无数据");
        }

        Console.WriteLine(new string('=', 80) + "\n");
    }

    /// <summary>
    /// 打印十六进制转储
    /// </summary>
    private void PrintHexDump(byte[] data)
    {
        const int bytesPerLine = 16;
        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            var line = data.Skip(i).Take(bytesPerLine).ToArray();
            var hex = string.Join(" ", line.Select(b => b.ToString("X2")));
            var ascii = new string(line.Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
            Console.WriteLine($"{i:X4}: {hex,-48} | {ascii}");
        }
    }

    /// <summary>
    /// 打印简化的包信息（单行）
    /// </summary>
    public void PrintPacketSummary(PacketInfo packet)
    {
        var parts = new List<string>
        {
            packet.Timestamp.ToString("HH:mm:ss.fff")
        };

        if (!string.IsNullOrEmpty(packet.SourceIp))
            parts.Add($"From: {packet.SourceIp}");
        if (packet.SourcePort.HasValue)
            parts.Add($":{packet.SourcePort}");

        parts.Add("->");

        if (!string.IsNullOrEmpty(packet.DestinationIp))
            parts.Add($"{packet.DestinationIp}");
        if (packet.DestinationPort.HasValue)
            parts.Add($":{packet.DestinationPort}");

        if (!string.IsNullOrEmpty(packet.TransportProtocol))
            parts.Add($"[{packet.TransportProtocol}]");

        if (packet.PayloadLength > 0)
            parts.Add($"Len: {packet.PayloadLength}");

        Console.WriteLine(string.Join(" ", parts));
    }
}

