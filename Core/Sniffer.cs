using System.Linq;
using System.Text;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using PacketSniffer.Models;

namespace PacketSniffer.Core;

public class Sniffer
{
    private static readonly string[] VirtualKeywords =
    {
        "vmware", "hyper-v", "vethernet", "nordvpn", "wireguard",
        "virtualbox", "virtual", "vnic"
    };

    private ICaptureDevice? _device;
    private bool _isRunning = false;

    /// <summary>
    /// 允许的端口列表，null 表示不过滤（监听所有端口）
    /// </summary>
    public HashSet<int>? AllowedPorts { get; set; }

    /// <summary>
    /// 是否按源端口过滤
    /// </summary>
    public bool FilterBySourcePort { get; set; } = true;

    /// <summary>
    /// 是否按目标端口过滤
    /// </summary>
    public bool FilterByDestinationPort { get; set; } = true;

    /// <summary>
    /// 优先选择的网卡关键字（从 Name/Description 中模糊匹配）
    /// 由外部配置注入；为空则使用自动选择策略。
    /// </summary>
    public string? PreferredDeviceKeyword { get; set; }

    /// <summary>
    /// 数据包捕获事件
    /// 参数：payload, sourcePort, destinationPort, protocol
    /// </summary>
    public event Action<byte[], int, int, string>? OnPacketCaptured;

    /// <summary>
    /// 完整数据包信息捕获事件
    /// </summary>
    public event Action<PacketInfo>? OnFullPacketCaptured;

    public void Start()
    {
        if (_isRunning)
            return;

        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0)
        {
            throw new InvalidOperationException("No network devices found");
        }

        // 根据配置关键字选择网卡；如果未配置或匹配失败，则使用自动策略
        var selected = SelectDeviceByKeyword(devices, PreferredDeviceKeyword) ?? SelectBestDevice(devices) ?? devices[0];

        
        Console.WriteLine();
        Console.WriteLine($"Using device (from config/auto): {selected.Description ?? selected.Name}");

        _device = selected;

        _device.Open(DeviceModes.Promiscuous, 1000);
        _device.OnPacketArrival += Device_OnPacketArrival;
        _device.StartCapture();
        _isRunning = true;

        Console.WriteLine("Packet capture started. Press Ctrl+C to stop.");
    }

    public void Stop()
    {
        if (!_isRunning || _device == null)
            return;

        _device.StopCapture();
        _device.OnPacketArrival -= Device_OnPacketArrival;
        _device.Close();
        _isRunning = false;

        Console.WriteLine("Packet capture stopped.");
    }

    private void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            byte[]? payload = null;
            int sourcePort = 0;
            int destinationPort = 0;
            string protocol = string.Empty;

            if (packet.Extract<TcpPacket>() is { } tcpPacket)
            {
                payload = tcpPacket.PayloadData;
                sourcePort = tcpPacket.SourcePort;
                destinationPort = tcpPacket.DestinationPort;
                protocol = "TCP";
            }
            else if (packet.Extract<UdpPacket>() is { } udpPacket)
            {
                payload = udpPacket.PayloadData;
                sourcePort = udpPacket.SourcePort;
                destinationPort = udpPacket.DestinationPort;
                protocol = "UDP";
            }

            // 构建完整包信息
            var packetInfo = BuildPacketInfo(rawPacket, packet, payload, sourcePort, destinationPort, protocol);
            OnFullPacketCaptured?.Invoke(packetInfo);

            if (payload != null && payload.Length > 0 && ShouldProcessPacket(sourcePort, destinationPort))
            {
                OnPacketCaptured?.Invoke(payload, sourcePort, destinationPort, protocol);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing packet: {ex.Message}");
        }
    }

    private bool ShouldProcessPacket(int sourcePort, int destinationPort)
    {
        if (AllowedPorts == null || AllowedPorts.Count == 0)
            return true;

        var matchSource = FilterBySourcePort && sourcePort > 0 && AllowedPorts.Contains(sourcePort);
        var matchDestination = FilterByDestinationPort && destinationPort > 0 && AllowedPorts.Contains(destinationPort);
        return matchSource || matchDestination;
    }

    private ICaptureDevice? SelectBestDevice(CaptureDeviceList devices)
    {
        ICaptureDevice? Pick(Func<ICaptureDevice, bool> predicate) =>
            devices.FirstOrDefault(predicate);

        bool IsVirtual(ICaptureDevice dev)
        {
            var text = $"{dev.Name} {dev.Description}".ToLowerInvariant();
            return VirtualKeywords.Any(k => text.Contains(k));
        }

        bool IsLoopback(ICaptureDevice dev)
        {
            var text = $"{dev.Name} {dev.Description}".ToLowerInvariant();
            return text.Contains("loopback");
        }

        bool IsNpcapLoopback(ICaptureDevice dev)
        {
            var text = $"{dev.Name} {dev.Description}".ToLowerInvariant();
            return text.Contains("npcap loopback");
        }

        var realDevice = Pick(d => !IsVirtual(d) && !IsLoopback(d));
        if (realDevice != null)
        {
            Console.WriteLine("Auto-selected physical NIC.");
            return realDevice;
        }

        var npcapLoop = Pick(IsNpcapLoopback);
        if (npcapLoop != null)
        {
            Console.WriteLine("Falling back to Npcap Loopback Adapter.");
            return npcapLoop;
        }

        var loopback = Pick(IsLoopback);
        if (loopback != null)
        {
            Console.WriteLine("Using loopback adapter.");
            return loopback;
        }

        Console.WriteLine("No real NIC found, using first available adapter.");
        return devices.FirstOrDefault();
    }

    private ICaptureDevice? SelectDeviceByKeyword(CaptureDeviceList devices, string? keyword)
    {
        if (string.IsNullOrWhiteSpace(keyword))
            return null;

        var lower = keyword.ToLowerInvariant();
        return devices.FirstOrDefault(d =>
            ($"{d.Name} {d.Description}").ToLowerInvariant().Contains(lower));
    }

    private string GetDeviceTag(ICaptureDevice dev)
    {
        var text = $"{dev.Name} {dev.Description}".ToLowerInvariant();

        bool isVirtual = VirtualKeywords.Any(k => text.Contains(k));
        bool isLoopback = text.Contains("loopback");
        bool isNpcapLoopback = text.Contains("npcap loopback");

        if (isNpcapLoopback) return "[LOOPBACK/NPCAP]";
        if (isLoopback) return "[LOOPBACK]";
        if (isVirtual) return "[VIRTUAL]";
        return "[PHYSICAL]";
    }

    private PacketInfo BuildPacketInfo(RawCapture rawPacket, Packet packet, byte[]? payload, int sourcePort, int destinationPort, string transportProtocol)
    {
        var packetInfo = new PacketInfo
        {
            Timestamp = rawPacket.Timeval.Date,
            Length = rawPacket.Data.Length,
            LinkLayerType = rawPacket.LinkLayerType.ToString(),
            Payload = payload,
            TransportProtocol = string.IsNullOrWhiteSpace(transportProtocol) ? null : transportProtocol,
            SourcePort = sourcePort > 0 ? sourcePort : null,
            DestinationPort = destinationPort > 0 ? destinationPort : null
        };

        if (packet.Extract<EthernetPacket>() is { } ethernetPacket)
        {
            packetInfo.SourceMac = ethernetPacket.SourceHardwareAddress.ToString();
            packetInfo.DestinationMac = ethernetPacket.DestinationHardwareAddress.ToString();
        }

        if (packet.Extract<IPPacket>() is { } ipPacket)
        {
            packetInfo.NetworkProtocol = ipPacket.GetType().Name;
            packetInfo.SourceIp = ipPacket.SourceAddress.ToString();
            packetInfo.DestinationIp = ipPacket.DestinationAddress.ToString();
            packetInfo.IpVersion = (int)ipPacket.Version;
            packetInfo.IpHeaderLength = ipPacket.HeaderLength;
            packetInfo.Ttl = ipPacket.TimeToLive;
        }
        else if (packet.Extract<IPv6Packet>() is { } ipv6Packet)
        {
            packetInfo.NetworkProtocol = "IPv6";
            packetInfo.SourceIp = ipv6Packet.SourceAddress.ToString();
            packetInfo.DestinationIp = ipv6Packet.DestinationAddress.ToString();
            packetInfo.IpVersion = 6;
            packetInfo.IpHeaderLength = ipv6Packet.HeaderLength;
            packetInfo.Ttl = ipv6Packet.HopLimit;
        }

        if (packet.Extract<TcpPacket>() is { } tcpPacket)
        {
            try
            {
                var flagsString = tcpPacket.Flags.ToString();
                if (!string.IsNullOrEmpty(flagsString) && flagsString != "0" && flagsString != "None")
                {
                    packetInfo.TcpFlags = flagsString;
                }
            }
            catch
            {
                packetInfo.TcpFlags = null;
            }

            packetInfo.TcpSequenceNumber = tcpPacket.SequenceNumber;
            packetInfo.TcpAcknowledgmentNumber = tcpPacket.AcknowledgmentNumber;
        }

        if (packet.Extract<UdpPacket>() is { } udpPacket)
        {
            packetInfo.UdpLength = udpPacket.Length;
        }

        if (payload != null && payload.Length > 0)
        {
            var maxBytes = Math.Min(256, payload.Length);
            var payloadSlice = payload.Take(maxBytes).ToArray();
            packetInfo.PayloadHex = BitConverter.ToString(payloadSlice).Replace("-", " ");

            try
            {
                var text = Encoding.UTF8.GetString(payloadSlice);
                packetInfo.PayloadText = new string(text.Where(c =>
                    char.IsControl(c)
                        ? c is '\n' or '\r' or '\t'
                        : char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsSymbol(c) || char.IsWhiteSpace(c)
                ).ToArray());
            }
            catch
            {
                packetInfo.PayloadText = null;
            }
        }

        return packetInfo;
    }
}

