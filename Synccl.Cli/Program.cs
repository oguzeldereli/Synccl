
using Spectre.Console.Cli;
using Synccl.Cli.Commands;

var app = new CommandApp();

app.Configure(config =>
{
    config.SetApplicationName("synccl");
    config.SetApplicationVersion("1.0.0");

    // ---- Vault lifecycle ----
    config.AddCommand<InitCommand>("init").WithAlias("i")
        .WithDescription("Create a new vault (initialises the .synccl folder)");

    config.AddCommand<CreateVaultCommand>("create").WithAlias("c")
        .WithDescription("Add a new vault to an existing .synccl folder");

    config.AddCommand<DestroyCommand>("destroy").WithAlias("rm")
        .WithDescription("Destroy a vault and all its data");

    config.AddCommand<VaultInfoCommand>("vault").WithAlias("v")
        .WithDescription("Display vault information");

    config.AddCommand<ListVaultsCommand>("vaults").WithAlias("vs")
        .WithDescription("List all vaults");

    config.AddCommand<RenameVaultCommand>("rename")
        .WithDescription("Rename a vault");

    // ---- Single-item secrets ----
    config.AddCommand<SetSecretCommand>("set").WithAlias("s")
        .WithDescription("Set a secret value");

    config.AddCommand<GetSecretCommand>("get").WithAlias("g")
        .WithDescription("Get a secret value");

    config.AddCommand<UnsetSecretCommand>("unset").WithAlias("u")
        .WithDescription("Delete a secret");

    config.AddCommand<ListSecretsCommand>("list").WithAlias("ls")
        .WithDescription("List secrets in a namespace");

    // ---- Namespace management ----
    config.AddBranch("namespace", ns =>
    {
        ns.SetDescription("Namespace management");
        ns.AddCommand<AddNamespaceCommand>("add")
            .WithDescription("Add a namespace to a vault");
        ns.AddCommand<RemoveNamespaceCommand>("remove").WithAlias("rm")
            .WithDescription("Remove a namespace from a vault");
        ns.AddCommand<ListNamespacesCommand>("list").WithAlias("ls")
            .WithDescription("List namespaces in a vault");
    });

    // ---- Bulk operations ----
    config.AddCommand<DiffCommand>("diff")
        .WithDescription("Diff two vault namespaces");

    config.AddCommand<PushCommand>("push")
        .WithDescription("Push secrets from one namespace to another");

    config.AddCommand<PullCommand>("pull")
        .WithDescription("Pull secrets from one namespace to another");

    // ---- Import / Export / Run ----
    config.AddCommand<ImportCommand>("import").WithAlias("imp")
        .WithDescription("Import secrets from a file (env or csv)");

    config.AddCommand<ExportCommand>("export").WithAlias("exp")
        .WithDescription("Export secrets to a file (env or csv)");

    config.AddCommand<RunCommand>("run").WithAlias("r")
        .WithDescription("Run a process with secrets injected as environment variables");

    // ---- Protect / Unprotect ----
    config.AddCommand<ProtectCommand>("protect")
        .WithDescription("Add passphrase or key protection to a vault");

    config.AddCommand<UnprotectCommand>("unprotect")
        .WithDescription("Remove passphrase/key protection (revert to TPM-only)");

    // ---- Key rotation ----
    config.AddBranch("rotate", rotate =>
    {
        rotate.SetDescription("Key rotation commands");
        rotate.AddCommand<RotateVaultKeyCommand>("vault")
            .WithDescription("Rotate the vault master key");
        rotate.AddCommand<RotateNamespaceKeyCommand>("namespace").WithAlias("ns")
            .WithDescription("Rotate a namespace key");
        rotate.AddCommand<RotateItemKeyCommand>("key")
            .WithDescription("Rotate an item key");
    });
});

return app.Run(args);