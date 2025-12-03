using RabbitMQ.Client;
using System.Text;

namespace PacketSniffer.Messaging;


public class RabbitProducer
{
    private readonly IConnection _connection;
    private readonly IModel _channel;

    public RabbitProducer()
    {
        var factory = new ConnectionFactory()
        {
            HostName = "localhost",
            UserName = "guest",
            Password = "guest"
        };

        _connection = factory.CreateConnection();
        _channel = _connection.CreateModel();

        // 声明队列（确保存在）
        _channel.QueueDeclare(
            queue: "sniffer",
            durable: true,
            exclusive: false,
            autoDelete: false,
            arguments: null
        );
    }

    public void Send(string message)
    {
        var body = Encoding.UTF8.GetBytes(message);

        _channel.BasicPublish(
            exchange: "",
            routingKey: "sniffer",
            basicProperties: null,
            body: body
        );
    }
}
