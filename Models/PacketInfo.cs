namespace PacketSniffer.Models;

/// <summary>
/// 完整的数据包信息模型
/// </summary>
public class PacketInfo
{
    /// <summary>
    /// 时间戳
    /// </summary>
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// 数据包长度（字节）
    /// </summary>
    public int Length { get; set; }

    /// <summary>
    /// 链路层类型
    /// </summary>
    public string LinkLayerType { get; set; } = string.Empty;

    /// <summary>
    /// 源 MAC 地址
    /// </summary>
    public string? SourceMac { get; set; }

    /// <summary>
    /// 目标 MAC 地址
    /// </summary>
    public string? DestinationMac { get; set; }

    /// <summary>
    /// 网络层协议（IPv4/IPv6）
    /// </summary>
    public string? NetworkProtocol { get; set; }

    /// <summary>
    /// 源 IP 地址
    /// </summary>
    public string? SourceIp { get; set; }

    /// <summary>
    /// 目标 IP 地址
    /// </summary>
    public string? DestinationIp { get; set; }

    /// <summary>
    /// IP 版本（4 或 6）
    /// </summary>
    public int? IpVersion { get; set; }

    /// <summary>
    /// IP 头部长度
    /// </summary>
    public int? IpHeaderLength { get; set; }

    /// <summary>
    /// IP TTL（Time To Live）
    /// </summary>
    public int? Ttl { get; set; }

    /// <summary>
    /// 传输层协议（TCP/UDP/ICMP等）
    /// </summary>
    public string? TransportProtocol { get; set; }

    /// <summary>
    /// 源端口
    /// </summary>
    public int? SourcePort { get; set; }

    /// <summary>
    /// 目标端口
    /// </summary>
    public int? DestinationPort { get; set; }

    /// <summary>
    /// TCP 标志（SYN, ACK, FIN等）
    /// </summary>
    public string? TcpFlags { get; set; }

    /// <summary>
    /// TCP 序列号
    /// </summary>
    public uint? TcpSequenceNumber { get; set; }

    /// <summary>
    /// TCP 确认号
    /// </summary>
    public uint? TcpAcknowledgmentNumber { get; set; }

    /// <summary>
    /// UDP 长度
    /// </summary>
    public int? UdpLength { get; set; }

    /// <summary>
    /// Payload 数据
    /// </summary>
    public byte[]? Payload { get; set; }

    /// <summary>
    /// Payload 长度
    /// </summary>
    public int PayloadLength => Payload?.Length ?? 0;

    /// <summary>
    /// Payload 的十六进制表示（前256字节）
    /// </summary>
    public string? PayloadHex { get; set; }

    /// <summary>
    /// Payload 的文本表示（如果可读）
    /// </summary>
    public string? PayloadText { get; set; }
}

