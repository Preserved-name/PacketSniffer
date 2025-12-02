using PacketSniffer.Core;
using PacketSniffer.Parsers;
using PacketSniffer.Models;

namespace PacketSniffer;

class Program
{
    private static Sniffer? _sniffer;

    static void Main(string[] args)
    {
        // 检查是否使用完整包信息模式
        bool fullPacketMode = args.Contains("--full") || args.Contains("-f");

        if (fullPacketMode)
        {
            RunFullPacketMode(args);
        }
        else
        {
            RunParseMode(args);
        }
    }

    /// <summary>
    /// 运行协议解析模式（默认模式）
    /// </summary>
    private static void RunParseMode(string[] args)
    {
        Console.WriteLine("=== Packet Sniffer - Protocol Parse Mode ===");

        try
        {
            // 1. 初始化 Sniffer
            _sniffer = new Sniffer();

            // 2. 配置端口过滤（从命令行参数或使用默认配置）
            ConfigurePortFilter(_sniffer, args);

            // 3. 初始化 PacketRouter 并注册解析器
            var router = new PacketRouter();
            router.RegisterParser(new JsonParser());
            router.RegisterParser(new HttpParser());
            router.RegisterParser(new BinaryParser()); // 兜底解析器

            // 3.1 配置 HTTP 路径过滤（只对 HTTP 请求路径生效）
            ConfigureHttpPathFilter(router);

            // 4. 注册 Sniffer 的包捕获事件
            _sniffer.OnPacketCaptured += (payload, sourcePort, destPort, protocol) =>
            {
                router.Route(payload, sourcePort, destPort, protocol);
            };

            // 注册 Ctrl+C 处理
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Console.WriteLine("\nStopping packet capture...");
                _sniffer?.Stop();
                Environment.Exit(0);
            };

            // 5. 启动 Sniffer
            _sniffer.Start();

            // 6. 持续运行（阻塞主线程）
            Console.WriteLine("Press Ctrl+C to stop...");
            while (true)
            {
                Thread.Sleep(100);
            }
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
    private static void RunFullPacketMode(string[] args)
    {
        Console.WriteLine("=== Packet Sniffer - Full Packet Info Mode ===");
        Console.WriteLine("此模式将打印所有捕获数据包的完整信息\n");

        try
        {
            // 1. 初始化 Sniffer
            _sniffer = new Sniffer();

            // 2. 配置端口过滤（从命令行参数）
            ConfigurePortFilter(_sniffer, args);

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

            // 注册 Ctrl+C 处理
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Console.WriteLine("\n停止抓包...");
                _sniffer?.Stop();
                Environment.Exit(0);
            };

            // 5. 启动 Sniffer
            _sniffer.Start();

            // 6. 持续运行（阻塞主线程）
            Console.WriteLine("按 Ctrl+C 停止...\n");
            while (true)
            {
                Thread.Sleep(100);
            }
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
    /// 配置端口过滤
    /// 支持从命令行参数读取端口，格式：dotnet run [--full] [port1] [port2] ...
    /// 例如：dotnet run 80 443 8080
    /// 例如：dotnet run --full 80 443
    /// </summary>
    private static void ConfigurePortFilter(Sniffer sniffer, string[] args)
    {
        var ports = new HashSet<int>();

        // 从命令行参数解析端口（跳过 --full, -f 等选项）
        foreach (var arg in args)
        {
            if (arg == "--full" || arg == "-f")
                continue;

            if (int.TryParse(arg, out int port) && port > 0 && port <= 65535)
            {
                ports.Add(port);
            }
            else if (!arg.StartsWith("--") && !arg.StartsWith("-"))
            {
                Console.WriteLine($"警告: 无效的端口号 '{arg}'，已忽略");
            }
        }

        // 如果命令行没有指定端口，使用默认配置（监听所有端口）
        if (ports.Count == 0)
        {
            // 默认：监听所有端口
            sniffer.AllowedPorts = null;
            sniffer.FilterBySourcePort = true;
            sniffer.FilterByDestinationPort = true;
            Console.WriteLine("端口过滤: 已禁用（监听所有端口）");
            Console.WriteLine("提示: 使用命令行参数指定端口，例如: dotnet run 80 443 8080");
            Console.WriteLine("提示: 使用 --full 参数查看完整包信息，例如: dotnet run --full 80 443");
        }
        else
        {
            // 配置指定的端口
            sniffer.AllowedPorts = ports;
            sniffer.FilterBySourcePort = true;
            sniffer.FilterByDestinationPort = true;
            var portsList = string.Join(", ", ports.OrderBy(p => p));
            Console.WriteLine($"端口过滤: 已启用，监听端口: {portsList}");
            Console.WriteLine($"过滤模式: 源端口={sniffer.FilterBySourcePort}, 目标端口={sniffer.FilterByDestinationPort}");
        }
        Console.WriteLine();
    }

    /// <summary>
    /// 配置 HTTP 路径过滤
    /// 只对 HTTP 请求生效：request_line 里的 PATH 包含任意一个配置片段才会打印
    /// 默认不过滤（列表为空），只需在这里按需要添加路径关键字
    /// </summary>
    private static void ConfigureHttpPathFilter(PacketRouter router)
    {
        // 示例：只关注 /api/user 和 /api/order 相关的 HTTP 请求
        router.HttpPathFilters.Add("/api/purchase/enquiry/salePrice");
        // router.HttpPathFilters.Add("/api/order");

        // 默认：不过滤任何路径
        // 如果你想只看某个接口，比如 /WeatherForecast，可以这样写：
        // router.HttpPathFilters.Add("/WeatherForecast");
    }
}

