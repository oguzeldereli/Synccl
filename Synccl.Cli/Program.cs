
using Spectre.Console.Cli;

var app = new CommandApp();

app.Configure(config =>
{
    config.SetApplicationName("synccl");
    config.SetApplicationVersion("1.0.0");

});

return app.Run(args);