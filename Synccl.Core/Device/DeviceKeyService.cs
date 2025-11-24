// Synccl.Core.Team/DeviceKeys.cs
using System;
using Sodium;
using Synccl.Core.Keys;

namespace Synccl.Core.Device;

public sealed class DeviceKeyService
{
    private readonly IKeychain _keychain;

    public DeviceKeyService(IKeychain keychain)
        => _keychain = keychain;

    public (byte[] PublicKey, byte[] PrivateKey) GetOrCreate(string account)
    {
        if (_keychain.TryGetKey(account, out var priv))
        {
            if (priv.Length != 32)
                throw new InvalidOperationException("Stored device key is not 32-byte X25519 key.");

            var pub = ScalarMult.Base(priv);
            return (pub, priv);
        }

        var kp = PublicKeyBox.GenerateKeyPair();
        var privateKey = kp.PrivateKey;
        var publicKey = kp.PublicKey;

        if (!_keychain.TrySetKey(account, privateKey))
            throw new InvalidOperationException("Could not store private key in OS keychain.");

        return (publicKey, privateKey);
    }
}
