using System.Threading;
using PacketSniffer.Core;
using PacketSniffer.Parsers;
using PacketSniffer.Models;
using PacketSniffer.Config;

namespace PacketSniffer;

class Program
{
    private static Sniffer? _sniffer;
    private static readonly AppSettings _config = AppConfig.Load();

    static void Main(string[] args)
    {
        // 检查是否使用完整包信息模式
        bool fullPacketMode = args.Contains("--full") || args.Contains("-f");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("\nStopping packet capture...");
            _sniffer?.Stop();
            cts.Cancel();
        };

        if (fullPacketMode)
        {
            RunFullPacketMode(cts.Token);
        }
        else
        {
            RunParseMode(cts.Token);
        }
    }

    /// <summary>
    /// 运行协议解析模式（默认模式）
    /// </summary>
    private static void RunParseMode(CancellationToken token)
    {
        Console.WriteLine("=== Packet Sniffer - Protocol Parse Mode ===");

        try
        {
            // 1. 初始化 Sniffer
            _sniffer = new Sniffer();

            // 2. 根据配置文件设置网卡和端口过滤
            ConfigureSnifferFromConfig(_sniffer, _config);

            // 3. 初始化 PacketRouter 并注册解析器
            var router = new PacketRouter();
            router.RegisterParser(new JsonParser());
            router.RegisterParser(new HttpParser());
            router.RegisterParser(new BinaryParser()); // 兜底解析器

            // 3.1 配置 HTTP 路径过滤（只对 HTTP 请求路径生效）
            ConfigureHttpPathFilter(router, _config);

            // 4. 注册 Sniffer 的包捕获事件
            _sniffer.OnPacketCaptured += (payload, sourcePort, destPort, protocol) =>
            {
                router.Route(payload, sourcePort, destPort, protocol);
            };

            // 5. 启动 Sniffer
            _sniffer.Start();

            // 6. 等待取消（替代 busy-loop）
            Console.WriteLine("Press Ctrl+C to stop...");
            token.WaitHandle.WaitOne();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            Console.WriteLine($"Stack Trace: {ex.StackTrace}");
        }
        finally
        {
            _sniffer?.Stop();
        }
    }

    /// <summary>
    /// 运行完整包信息模式
    /// </summary>
    private static void RunFullPacketMode(CancellationToken token)
    {
        Console.WriteLine("=== Packet Sniffer - Full Packet Info Mode ===");
        Console.WriteLine("此模式将打印所有捕获数据包的完整信息\n");

        try
        {
            // 1. 初始化 Sniffer
            _sniffer = new Sniffer();

            // 2. 根据配置文件设置网卡和端口过滤
            ConfigureSnifferFromConfig(_sniffer, _config);

            // 3. 初始化包信息打印器
            var printer = new PacketPrinter(
                showPayload: true,
                maxPayloadBytes: 256,
                showHex: true,
                showText: true
            );

            // 4. 注册完整包信息捕获事件
            _sniffer.OnFullPacketCaptured += (packetInfo) =>
            {
                // 端口过滤检查
                if (ShouldProcessPacket(_sniffer, packetInfo))
                {
                    printer.PrintPacket(packetInfo);
                }
            };

            // 5. 启动 Sniffer
            _sniffer.Start();

            // 6. 等待取消（替代 busy-loop）
            Console.WriteLine("按 Ctrl+C 停止...\n");
            token.WaitHandle.WaitOne();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"错误: {ex.Message}");
            Console.WriteLine($"堆栈跟踪: {ex.StackTrace}");
        }
        finally
        {
            _sniffer?.Stop();
        }
    }

    /// <summary>
    /// 检查是否应该处理该数据包（端口过滤）
    /// </summary>
    private static bool ShouldProcessPacket(Sniffer sniffer, PacketInfo packetInfo)
    {
        // 如果没有配置端口过滤，处理所有包
        if (sniffer.AllowedPorts == null || sniffer.AllowedPorts.Count == 0)
            return true;

        // 如果没有端口信息，不处理
        if (!packetInfo.SourcePort.HasValue && !packetInfo.DestinationPort.HasValue)
            return false;

        // 检查源端口
        if (sniffer.FilterBySourcePort && 
            packetInfo.SourcePort.HasValue && 
            sniffer.AllowedPorts.Contains(packetInfo.SourcePort.Value))
            return true;

        // 检查目标端口
        if (sniffer.FilterByDestinationPort && 
            packetInfo.DestinationPort.HasValue && 
            sniffer.AllowedPorts.Contains(packetInfo.DestinationPort.Value))
            return true;

        return false;
    }

    /// <summary>
    /// 根据配置文件设置 Sniffer 的端口过滤和网卡关键字
    /// </summary>
    private static void ConfigureSnifferFromConfig(Sniffer sniffer, AppSettings config)
    {
        // 配置端口过滤
        if (config.Ports is { Count: > 0 })
        {
            sniffer.AllowedPorts = new HashSet<int>(config.Ports);
            sniffer.FilterBySourcePort = config.FilterSourcePort;
            sniffer.FilterByDestinationPort = config.FilterDestinationPort;

            var portsList = string.Join(", ", sniffer.AllowedPorts.OrderBy(p => p));
            Console.WriteLine($"端口过滤: 已启用，监听端口: {portsList}");
            Console.WriteLine($"过滤模式: 源端口={sniffer.FilterBySourcePort}, 目标端口={sniffer.FilterByDestinationPort}");
        }
        else
        {
            sniffer.AllowedPorts = null;
            sniffer.FilterBySourcePort = true;
            sniffer.FilterByDestinationPort = true;
            Console.WriteLine("端口过滤: 已禁用（监听所有端口）");
        }

        // 配置网卡关键字
        sniffer.PreferredDeviceKeyword = string.IsNullOrWhiteSpace(config.DeviceKeyword)
            ? null
            : config.DeviceKeyword;

        if (!string.IsNullOrWhiteSpace(config.DeviceKeyword))
        {
            Console.WriteLine($"网卡关键字: \"{config.DeviceKeyword}\"（将优先匹配 Name/Description）");
        }

        Console.WriteLine();
    }

    /// <summary>
    /// 配置 HTTP 路径过滤
    /// 只对 HTTP 请求生效：request_line 里的 PATH 包含任意一个配置片段才会打印
    /// 路径关键字从配置文件 AppSettings.HttpPathFilters 读取
    /// </summary>
    private static void ConfigureHttpPathFilter(PacketRouter router, AppSettings config)
    {
        router.HttpPathFilters.Clear();

        if (config.HttpPathFilters is { Count: > 0 })
        {
            foreach (var filter in config.HttpPathFilters.Where(f => !string.IsNullOrWhiteSpace(f)))
            {
                router.HttpPathFilters.Add(filter);
            }

            Console.WriteLine("HTTP 路径过滤已启用，关键字列表：");
            foreach (var f in router.HttpPathFilters)
            {
                Console.WriteLine($"  - {f}");
            }
        }
        else
        {
            Console.WriteLine("HTTP 路径过滤未配置，所有 HTTP 请求路径都会打印。");
        }

        Console.WriteLine();
    }
}

