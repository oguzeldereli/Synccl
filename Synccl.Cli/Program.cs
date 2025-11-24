
using Spectre.Console.Cli;
using Synccl.Cli.Commands;
using Synccl.Cli.Commands.Env;
using Synccl.Cli.Commands.Namespace;
using Synccl.Cli.Commands.Namespaces;
using Synccl.Cli.Commands.Remote;
using Synccl.Cli.Settings.Namespace;
using Synccl.Cli.Settings.Remote.Add;

var app = new CommandApp();

app.Configure(config =>
{
    config.SetApplicationName("synccl");
    config.SetApplicationVersion("1.0.0");

    // init and destroy
    config.AddCommand<InitCommand>("init")
        .WithAlias("i")
        .WithDescription("Initialize a new synccl vault and configuration in the specified directory.");
    config.AddCommand<DestroyCommand>("destroy")
        .WithAlias("rm")
        .WithDescription("Destroy the local synccl vault and optionally the configuration file.");

    // manage vault configurations
    config.AddCommand<SetCommand>("set")
        .WithAlias("s")
        .WithDescription("Set a configuration key-value pair in the vault.");
    config.AddCommand<GetCommand>("get")
        .WithAlias("g")
        .WithDescription("Get the value of a configuration key from the vault.");
    config.AddCommand<UnsetCommand>("unset")
        .WithAlias("un")
        .WithDescription("Unset a configuration key-value pair from the vault.");
    config.AddCommand<ListCommand>("list")
        .WithAlias("ls")
        .WithDescription("List all configuration key-value pairs in the vault.");

    // remote operations
    config.AddCommand<DiffCommand>("diff")
        .WithDescription("Compare local vault configurations with a remote storage.");
    config.AddCommand<PushCommand>("push")
        .WithDescription("Push local vault configurations to a remote storage.");
    config.AddCommand<PullCommand>("pull")
        .WithDescription("Pull vault configurations from a remote storage to the local vault.");

    // manage env files
    config.AddBranch("env", env =>
    {
        env.SetDescription("Manage .env file interactions with the vault");

        env.AddCommand<EnvPullCommand>("pull")
            .WithDescription("Save the vault configurations to a .env file.");
        env.AddCommand<EnvPushCommand>("push")
            .WithDescription("Load configurations from a .env file into the vault.");
        env.AddCommand<EnvDiffCommand>("diff")
            .WithDescription("Compare the vault configurations with a .env file.");
    });

    // manage namespaces
    config.AddBranch("namespaces", ns =>
    {
        ns.SetDescription("Manage namespaces within the vault");

        ns.AddCommand<NamespacesCreateCommand>("create")
            .WithDescription("Create a new namespace in the vault.")
            .WithAlias("add");
        ns.AddCommand<NamespaceDeleteCommand>("delete")
            .WithDescription("Delete an existing namespace from the vault.")
            .WithAlias("rm");
        ns.AddCommand<NamespacesListCommand>("list")
            .WithDescription("List all namespaces in the vault.")
            .WithAlias("ls");
    }).WithAlias("nss");

    // manage a specific namespace
    config.AddBranch<NamespaceCommandSettings>("namespace", ns =>
    {
        ns.SetDescription("Manage a specific namespace");

        ns.AddCommand<NamespaceListCommand>("list")
            .WithDescription("List all key-value pairs in a specific namespace.")
            .WithAlias("ls");
        ns.AddCommand<NamespaceGetCommand>("get")
            .WithDescription("Get a key-value pair from a specific namespace.")
            .WithAlias("g");
        ns.AddCommand<NamespaceSetCommand>("set")
            .WithDescription("Set a key-value pair in a specific namespace.")
            .WithAlias("s");
        ns.AddCommand<NamespaceUnsetCommand>("unset")
            .WithDescription("Unset a key-value pair from a specific namespace.")
            .WithAlias("un");
        ns.AddCommand<NamespacePullCommand>("pull")
            .WithDescription("Pull all key-value pairs from a specific source namespace to target namespace without deleting existing ones.");
        ns.AddCommand<NamespacePushCommand>("push")
            .WithDescription("Push all key-value pairs from a specific source namespace to target namespace, without deleting existing ones.");
        ns.AddCommand<NamespaceDiffCommand>("diff")
            .WithDescription("Compare key-value pairs between two namespaces.");
    }).WithAlias("ns");

    // manage remote storage
    config.AddBranch("remote", remote =>
    {
        remote.SetDescription("Manage remote vault storage");

        remote.AddCommand<RemoteRemoveCommand>("remove")
            .WithDescription("Remove a remote storage configuration")
            .WithAlias("rm");

        remote.AddBranch<RemoteAddCommandSettings>("add", add =>
        {
            add.SetDescription("Add a new remote storage configuration");

            add.AddCommand<RemoteAddS3Command>("s3")
                .WithDescription("Configure S3 as remote vault storage");
        });
    });
});

return app.Run(args);