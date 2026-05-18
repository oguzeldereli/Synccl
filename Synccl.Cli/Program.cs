
using Spectre.Console.Cli;

var app = new CommandApp();

app.Configure(config =>
{
    config.SetApplicationName("synccl");
    config.SetApplicationVersion("1.0.0");

    /* 
     * All commands to be added
     * init|i <--vault,-v=default> <--defaultNamespace,-defaultNs=default> <--type,-t=local>
     *      creates a vault with the given name and default namespace with the given type
     *      
     * destroy|rm <--vault,-v=default>
     *      destroys the vault with the given name, all data will be lost
     * 
     * set|s <vault:ns:key=default:default:key> <value>
     *      sets the value of the given key in the given vault and namespace, 
     *      if the key already exists, it will be overwritten
     * 
     * get|g <vault:ns:key=default:default:key>
     *      gets the value of the given key in the given vault and namespace
     * 
     * unset|u <vault:ns:key=default:default:key>
     *      unsets the value of the given key in the given vault and namespace
     * 
     * list|ls <vault:ns=default:default> [--values,-v]
     *      lists all keys (and optionally values) in the given vault and namespace
     * 
     * push <vault:ns=default:default> <vault:ns=default:default> [--dry-run,-d]
     *      pushes the contents of the source vault and namespace 
     *      to the destination vault and namespace
     *      
     * pull <vault:ns=default:default> <vault:ns=default:default> [--dry-run,-d]
     *      pulls the contents of the source vault and namespace
     *      to the destination vault and namespace
     *      
     * diff <vault:ns=default:default> <vault:ns=default:default>
     *      compares the contents of the source vault and namespace with 
     *      the destination vault and namespace
     * 
     * import|imp <vault:ns=default:default> <path> [--format,-f=<env|csv>]
     *      imports environment variables from the file at <path> to the 
     *      given vault and namespace,
     * 
     * export|exp <vault:ns=default:default> <path> [--format,-f=<env|csv>]
     *      exports environment variables from the given vault and namespace 
     *      to a file at <path> with the given format
     * 
     * run|r <vault:ns=default:default> <path>
     *      runs the executable at <path> with the environment variables from the 
     *      given vault and namespace
     *      
     * protect <vault=default> [--passphrase|--public-key]
     *      protect the mounted vault with the given method,
     *      if the vault is already protected, it will be re-protected with the new method
     * 
     * unprotect <vault=default>
     *      unprotect the mounted vault
     * 
     * rotate vault <vault=default> [--all,-a]
     *      rotate the vault master key and if --all is specified, 
     *      also rotate all namespace and item keys in the vault
     * 
     * rotate namespace <vault:ns=default:default> [--all,-a]
     *      rotate the namespace key and if --all is specified, 
     *      also rotate all item keys in the namespace
     * 
     * rotate key <vault:ns:key=default:default:key> 
     *      rotate a item key
     * 
     * vault|v <vault=default>
     *      displays information about the given vault
     * 
     *** vault|v <vault=default> set <ns:key=default:key> <value>
     *      sets the value of the given key in the given vault and namespace
     *  
     *** vault|v <vault=default> get <ns:key=default:key>
     *      gets the value of the given key in the given vault and namespace
     *  
     *** vault|v <vault=default> unset <ns:key=default:key>
     *      unsets the value of the given key in the given vault and namespace
     *  
     *** vault|v <vault=default> list <ns=default> [--values,-v]
     *      lists all keys (and optionally values) in the given vault and namespace
     *      
     *** vault|v <vault=default> run <ns=default> <path>   
     *      runs the executable at <path> with the environment variables from the 
     *      given vault and namespace
     *      
     *** vault|v <vault=default> name <newName>
     *      Changes the name of the vault to the given new name
     *      
     *** vault|v <vault=default> push <ns> <vault:ns> [--dry-run,-d]
     *      pushes the contents of the source vault and namespace to 
     *      the destination vault and namespace
     *
     *** vault|v <vault=default> pull <ns> <vault:ns> [--dry-run,-d]
     *      pulls the contents of the source vault and namespace
     *      to the destination vault and namespace
     *
     *** vault|v <vault=default> diff <ns> <vault:ns>
     *      compares the contents of the source vault and namespace with
     *      the destination vault and namespace
     * 
     *** vault|v <vault=default> namespaces|nss
     *      lists all namespaces in the vault
     *      
     *** vault|v <vault=default> namespaces|nss add <ns>
     *      adds a namespace to the vault with the given name
     *      
     *** vault|v <vault=default> namespaces|nss remove|rm <ns>
     *      removes the namespace with the given name from the vault, 
     *      all data in the namespace will be lost
     *      
     *** vault|v <vault=default> namespace|ns <ns=default>
     *      displays information about the given namespace
     *
     *** vault|v <vault=default> namespace|ns <ns=default> set|s <key> <value>
     *      sets the value of the given key in the given vault and namespace
     * 
     *** vault|v <vault=default> namespace|ns <ns=default> get|g <key>
     *      gets the value of the given key in the given vault and namespace
     *      
     *** vault|v <vault=default> namespace|ns <ns=default> unset|u <key>
     *      unsets the value of the given key in the given vault and namespace
     *
     *** vault|v <vault=default> namespace|ns <ns=default> list|ls [--values,-v]
     *      lists all keys (and optionally values) in the given vault and namespace
     *      
     *** vault|v <vault=default> namespace|ns <ns=default> run|r <path>
     *      runs the executable at <path> with the environment variables from the
     *      namespace
     *     
     *** vault|v <vault=default> namespace|ns <ns=default> push <vault:ns> [--dry-run,-d]
     *      pushes the contents of the source namespace to the destination vault and namespace
     *      
     *** vault|v <vault=default> namespace|ns <ns=default> pull <vault:ns> [--dry-run,-d]
     *      pulls the contents of the source namespace to the destination vault and namespace
     *      
     *** vault|v <vault=default> namespace|ns <ns=default> diff <vault:ns>
     *      compares the contents of the source namespace with the destination vault and namespace
     *
     *** vault|v <vault=default> export|exp <ns=default> <path> [--format,-f=<env|csv>]
     *      exports environment variables from the given namespace to a file at <path> with the given format
     *      
     *** vault|v <vault=default> import|imp <ns=default> <path> [--format,-f=<env|csv>]
     *      imports environment variables from the file at <path> to the given namespace
     *
     *** vault|v <vault=default> protect [--passphrase|--public-key]
     *
     *** vault|v <vault=default> unprotect
     *
     *** vault|v <vault=default> rotate vault [--all,-a]
     *
     *** vault|v <vault=default> rotate namespace <ns> [--all,-a]
     *
     *** vault|v <vault=default> rotate key <ns:key> 
     *
     * vaults|vs [vault=default]
     *      lists all vaults
     * 
     *** vaults|vs init|i <vault> [defaultNamespace=default]
     *      creates a vault with the given name and default namespace
     *      
     *** vaults|vs destroy|rm <vault>
     *      destroys the vault with the given name
     * 
     * mount|m <vault=default> <path> [--passphrase|--public-key]
     *      mounts an unmounted vault to the given path with the given method
     * 
     * unmount|um <vault=default> <path> [--passphrase|--public-key]
     *      unmounts a vault into a portable file at the given path with the given method
     */
});

return app.Run(args);