# Synccl

A local-first secrets manager for developers. Secrets live in encrypted vaults inside the
repository that uses them, in a `.synccl/` folder found the same way Git finds `.git/`,
and each vault is sealed to the hardware of the machine it lives on. Copying a vault file
to another machine gets an attacker nothing; moving a vault on purpose is an explicit
`unmount` → `mount`, protected by a passphrase or an X25519 key.

No server, no account, no sync service.

## How a vault is protected

```
vault master key   (32 bytes)   sealed by the device: TPM 2.0 or Secure Enclave
  └─ namespace key (32 bytes)   wrapped by the vault master key
       └─ item key (32 bytes)   wrapped by the namespace key
            └─ value            XChaCha20-Poly1305
```

Every secret has its own key, so any level can be rotated without touching the others
(`synccl rotate vault|namespace|key`), and reading one secret decrypts only that secret.

| platform | device binding |
|---|---|
| Windows | TPM 2.0 through TBS: an AES-256 key created under the TPM's storage primary |
| Linux | TPM 2.0 through the kernel TPM device, same scheme |
| macOS | Secure Enclave P-256 key (non-extractable) wraps a per-blob AES-256-GCM key, through a native bridge (`libSecureEnclaveBridge.dylib`) |

The TPM's sealed key blobs are stored in `%APPDATA%\synccl\` or `~/.config/synccl/`. They are
encrypted by the TPM and useless without it. The storage primary is re-derived and the
AES key loaded once per process and reused for every wrap and unwrap, rather than once per
operation.

### Moving a vault between machines

`unmount` unwraps the master key with this device, rewraps it for transport, and **removes
the device wrap**, producing a portable `<vault>.vault.json.unmounted` file:

- **passphrase**: Argon2id (256 MiB, 4 passes) → XChaCha20-Poly1305
- **public key**: ephemeral X25519 key agreement → HKDF-SHA256 → XChaCha20-Poly1305

`mount` on the destination reverses it: unwrap with the passphrase or private key, seal to
the new device, and drop the transport wrap.

## Install

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/).

```bash
git clone https://github.com/oguzeldereli/Synccl
cd Synccl
dotnet publish Synccl.Cli -c Release -r linux-x64     # or win-x64, win-arm64, osx-x64, osx-arm64
```

On Linux your user needs read/write access to the TPM device (usually membership of the
`tss` group).

## Usage

Targets are written `vault:namespace:key`. Missing parts default to `default`, so
`API_KEY` means `default:default:API_KEY`.

```bash
synccl init                              # create .synccl/ and the default vault
synccl set dev:API_KEY sk-123            # set a secret in namespace "dev"
synccl get dev:API_KEY
synccl list dev --values
synccl run dev node server.js            # run a process with the namespace as env vars

synccl namespace add default prod
synccl diff default:dev default:prod
synccl push default:dev default:prod --dry-run

synccl import dev .env                   # env (default) or --format csv
synccl export dev secrets.csv --format csv

synccl rotate vault --all                # new master key, and every key below it
synccl unmount --passphrase              # portable file, protected by a passphrase
synccl mount default.vault.json.unmounted --passphrase
```

`synccl --help` and `synccl <command> --help` list every command and option.

## No hardware, no vault

Synccl will not run without a TPM 2.0 or the Secure Enclave. There is no software
fallback: a vault's protection is its hardware binding, and any key Synccl could derive
without hardware, an attacker holding the vault file could derive too.

Earlier versions did fall back when no TPM was available, deriving the key from the
machine's hostname on Linux and macOS and using DPAPI on Windows. Vaults sealed that way
cannot be opened by the current version.

## Known issues

- `unmount --private-key <path>` expects the **recipient's X25519 public key** file,
  despite the flag's name. `mount --private-key` expects the matching private key.
- There is no command for generating an X25519 key pair yet.
- In `--help`, `mount` is described as caching credentials for the session. It actually
  imports an `.unmounted` file and binds it to this device.

## License

[Elastic License 2.0](LICENSE): source-available. You may use, modify and redistribute it,
but not offer it as a hosted or managed service.
