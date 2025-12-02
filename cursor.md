\# Cursor 全自动构建：实时抓包 + 协议解析 + 业务分发项目



请按照以下指令为我创建并完善整个 C# 项目结构。



---



\# 1. 创建项目结构



请帮我创建一个 C# 控制台项目，用于实时网络抓包与协议解析。  

项目结构如下：



/PacketSniffer  

&nbsp; /Core  

&nbsp;    - Sniffer.cs           // 抓包核心：SharpPcap  

&nbsp;    - PacketRouter.cs      // 分发到不同解析器  

&nbsp; /Parsers  

&nbsp;    - IParser.cs           // 解析器接口  

&nbsp;    - JsonParser.cs        // JSON 协议解析  

&nbsp;    - HttpParser.cs        // HTTP 协议解析  

&nbsp;    - BinaryParser.cs      // 二进制协议解析（兜底）  

&nbsp; /Models  

&nbsp;    - ParsedResult.cs      // 通用解析模型  

&nbsp; Program.cs                // 启动入口  



请创建上述文件并写好最基础骨架结构。



---



\# 2. 编写 Sniffer.cs（实时抓包模块）



请为 Core/Sniffer.cs 编写实时抓包类，要求：



\- 使用 SharpPcap + PacketDotNet  

\- 自动选择第一块网卡  

\- 开启混杂模式  

\- 每当收到包时触发事件：  

&nbsp; `OnPacketCaptured(byte\[] rawPayload)`  

\- 提取 TCP/UDP payload 并丢给 PacketRouter  

\- API：  

&nbsp; - Start()  

&nbsp; - Stop()  



---



\# 3. 编写 PacketRouter.cs（自动选择解析器）



请为 Core/PacketRouter.cs 实现解析路由器：



功能要求：



1\. 内部维护 List<IParser> 解析器列表  

2\. 调用顺序：JsonParser → HttpParser → BinaryParser  

3\. 满足 CanParse() 的解析器负责 Parse()  

4\. 得到 ParsedResult 后打印内容  

5\. 调用业务逻辑入口：  

&nbsp;  `HandleBusinessLogic(ParsedResult result)`  



---



\# 4. 编写通用解析器接口 IParser.cs



请为 Parsers/IParser.cs 编写接口：



```csharp

bool CanParse(byte\[] payload);

ParsedResult Parse(byte\[] payload);

```



CanParse 返回 false 则不解析。  

Parse 错误请 throw。



---



\# 5. 实现 JsonParser.cs



请为 Parsers/JsonParser.cs 实现 JSON 协议解析器：



\- 判断 payload 是否为 JSON  

\- 使用 JObject 解析所有一级字段  

\- ParsedResult 的内容结构：  

&nbsp; - Protocol = "json"  

&nbsp; - Fields = Dictionary<string,string> 自动填充所有 JSON 字段  



解析失败则 CanParse = false。



---



\# 6. 实现 HttpParser.cs



请为 Parsers/HttpParser.cs 实现 HTTP 协议解析器：



\- 判断是否是 HTTP 包（以 GET/POST/HTTP/1 开头）  

\- 解析 HTTP Header  

\- Body 如果是 JSON，则自动解析字段加入 Fields  

\- 输出格式：  

&nbsp; Protocol = "http"  

&nbsp; Fields = headers + parsedJsonFields  



---



\# 7. 实现 BinaryParser.cs（兜底解析器）



请为 Parsers/BinaryParser.cs 写一个兜底解析器：



\- CanParse 永远返回 true  

\- Parse() 返回：  

&nbsp; Protocol = "binary"  

&nbsp; Fields = { "hex" = payload 的十六进制字符串 }



这个解析器用于未来扩展自定义协议。



---



\# 8. 实现 ParsedResult.cs



请编写 Models/ParsedResult.cs：



内容：



```csharp

class ParsedResult

{

&nbsp;   public string Protocol { get; set; }

&nbsp;   public Dictionary<string,string> Fields { get; set; } = new();



&nbsp;   public override string ToString()

&nbsp;   {

&nbsp;       // 格式化成可读文本输出

&nbsp;   }

}

```



---



\# 9. 完成 Program.cs（启动项目）



请为 Program.cs 编写主流程：



1\. 初始化 Sniffer  

2\. 注册并添加：JsonParser、HttpParser、BinaryParser  

3\. 启动 Sniffer.Start()  

4\. 持续运行（阻塞主线程）  

5\. 每条解析后的包，都打印协议类型与字段  



---



\# 10. 添加业务逻辑 HandleBusinessLogic()



请在 PacketRouter.cs 内添加：



```csharp

void HandleBusinessLogic(ParsedResult result)

```



默认业务逻辑如下：



\- 如果 Fields 包含 "userId"，打印 “检测到用户操作 userId=xxx”

\- 如果 action = "upload"，打印 “触发上传业务逻辑”

\- 如果是 HTTP 协议，且包含 Authorization，则打印 Token



这只是示例，你写出上述逻辑即可。



---



\# 11. 自动安装依赖



请生成一个响应，确保项目安装：



```

SharpPcap

PacketDotNet

Newtonsoft.Json

```



如果不存在请自动添加 NuGet。



---



\# 12. 未来扩展：自定义协议解析（可留接口）



请在 BinaryParser 保留扩展标记：



```

// TODO: 在此扩展自定义协议解析

```



---



\# 任务完成标准



当全部完成后：

\- 项目可构建

\- 可运行并抓取本机所有网络流量

\- 自动识别 JSON / HTTP / 二进制协议

\- 自动解析字段

\- 自动触发业务逻辑回调



实现完毕后请告诉我“项目结构与代码均已完成”。





