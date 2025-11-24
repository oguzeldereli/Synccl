using Sodium;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Synccl.Core.Crypto;

public static class Envelope
{
    private const int PublicKeyLen = 32;
    private const int PrivateKeyLen = 32;
    private const int NonceLen = 24;

    private static readonly byte[] HkdfSalt = new byte[32];
    private static readonly byte[] InfoPrefix = System.Text.Encoding.ASCII.GetBytes("synccl/x25519-wrap/v1");

    public static byte[] WrapDataWithKey(byte[] data, byte[] key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        var nonce = SodiumCore.GetRandomBytes(24);
        var aad = System.Text.Encoding.UTF8.GetBytes("synccl/data/v1");
        var ct = SecretAeadXChaCha20Poly1305.Encrypt(
            data,
            nonce,
            key,
            aad);
        var result = new byte[24 + ct.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, 24);
        Buffer.BlockCopy(ct, 0, result, 24, ct.Length);
        return result;
    }

    public static byte[] UnwrapDataWithKey(byte[] envelope, byte[] key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (envelope.Length < 24 + 16)
            throw new ArgumentException("Envelope too short", nameof(envelope));
        var nonce = new byte[24];
        var ct = new byte[envelope.Length - 24];
        Buffer.BlockCopy(envelope, 0, nonce, 0, 24);
        Buffer.BlockCopy(envelope, 24, ct, 0, ct.Length);
        var aad = System.Text.Encoding.UTF8.GetBytes("synccl/data/v1");
        return SecretAeadXChaCha20Poly1305.Decrypt(
            ct,
            nonce,
            key,
            aad);
    }

    public static byte[] WrapDekWithKey(byte[] dek, byte[] key)
    {
        if (dek.Length != 32)
            throw new ArgumentException("DEK must be 32 bytes", nameof(dek));
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));

        var nonce = SodiumCore.GetRandomBytes(24);
        var aad = System.Text.Encoding.UTF8.GetBytes("synccl/ik-nk/v1");

        var ct = SecretAeadXChaCha20Poly1305.Encrypt(
            dek,
            nonce,
            key,
            aad);

        var result = new byte[24 + ct.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, 24);
        Buffer.BlockCopy(ct, 0, result, 24, ct.Length);
        return result;
    }

    public static byte[] UnwrapDekWithKey(byte[] envelope, byte[] key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (envelope.Length < 24 + 16)
            throw new ArgumentException("Envelope too short", nameof(envelope));

        var nonce = new byte[24];
        var ct = new byte[envelope.Length - 24];

        Buffer.BlockCopy(envelope, 0, nonce, 0, 24);
        Buffer.BlockCopy(envelope, 24, ct, 0, ct.Length);

        var aad = System.Text.Encoding.UTF8.GetBytes("synccl/ik-nk/v1");

        return SecretAeadXChaCha20Poly1305.Decrypt(
            ct,
            nonce,
            key,
            aad);
    }

    public static byte[] WrapDekWithX25519(ReadOnlySpan<byte> dek, ReadOnlySpan<byte> recipientPublicKey)
    {
        if (dek.IsEmpty) throw new ArgumentException("DEK cannot be empty.", nameof(dek));
        if (recipientPublicKey.Length != PublicKeyLen) throw new ArgumentException("recipientPublicKey must be 32 bytes (X25519).", nameof(recipientPublicKey));

        var eph = PublicKeyBox.GenerateKeyPair(); 
        var ephPriv = eph.PrivateKey; 
        var ephPub = eph.PublicKey;

        var shared = ScalarMult.Mult(ephPriv, recipientPublicKey.ToArray()); 

        var info = BuildInfo(ephPub, recipientPublicKey);
        var aeadKey = HkdfSha256(shared, HkdfSalt, info, 32);

        var nonce = SodiumCore.GetRandomBytes(NonceLen);
        var aad = info;
        var ct = SecretAeadXChaCha20Poly1305.Encrypt(dek.ToArray(), nonce, aeadKey, aad);

        var result = new byte[PublicKeyLen + NonceLen + ct.Length];
        Buffer.BlockCopy(ephPub, 0, result, 0, PublicKeyLen);
        Buffer.BlockCopy(nonce, 0, result, PublicKeyLen, NonceLen);
        Buffer.BlockCopy(ct, 0, result, PublicKeyLen + NonceLen, ct.Length);

        CryptographicOperations.ZeroMemory(shared);
        CryptographicOperations.ZeroMemory(aeadKey);

        return result;
    }

    public static byte[] UnwrapDekWithX25519(ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> recipientPrivateKey, ReadOnlySpan<byte> recipientPublicKey)
    {
        if (envelope.Length < PublicKeyLen + NonceLen + 16)
            throw new ArgumentException("Envelope too short.", nameof(envelope));
        if (recipientPrivateKey.Length != PrivateKeyLen)
            throw new ArgumentException("recipientPrivateKey must be 32 bytes (X25519).", nameof(recipientPrivateKey));
        if (recipientPublicKey.Length != PublicKeyLen)
            throw new ArgumentException("recipientPublicKey must be 32 bytes (X25519).", nameof(recipientPublicKey));

        var ephPub = envelope.Slice(0, PublicKeyLen).ToArray();
        var nonce = envelope.Slice(PublicKeyLen, NonceLen).ToArray();
        var ct = envelope.Slice(PublicKeyLen + NonceLen).ToArray();

        var shared = ScalarMult.Mult(recipientPrivateKey.ToArray(), ephPub);

        var info = BuildInfo(ephPub, recipientPublicKey);
        var aeadKey = HkdfSha256(shared, HkdfSalt, info, 32);

        var aad = info;
        var dek = SecretAeadXChaCha20Poly1305.Decrypt(ct, nonce, aeadKey, aad);

        CryptographicOperations.ZeroMemory(shared);
        CryptographicOperations.ZeroMemory(aeadKey);

        return dek;
    }

    private static byte[] BuildInfo(byte[] ephPub, ReadOnlySpan<byte> recipPub)
    {
        var info = new byte[InfoPrefix.Length + ephPub.Length + recipPub.Length];
        Buffer.BlockCopy(InfoPrefix, 0, info, 0, InfoPrefix.Length);
        Buffer.BlockCopy(ephPub, 0, info, InfoPrefix.Length, ephPub.Length);
        Buffer.BlockCopy(recipPub.ToArray(), 0, info, InfoPrefix.Length + ephPub.Length, recipPub.Length);
        return info;
    }

    private static byte[] HkdfSha256(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int length)
    {
        using var hkdf = new HMACSHA256(salt.ToArray());
        var prk = hkdf.ComputeHash(ikm.ToArray());

        var okm = new byte[length];
        var t = Array.Empty<byte>();
        var counter = (byte)1;
        var pos = 0;

        while (pos < length)
        {
            hkdf.Key = prk;
            var data = Concat(t, info.ToArray(), new[] { counter });
            t = hkdf.ComputeHash(data);

            var toCopy = Math.Min(t.Length, length - pos);
            Buffer.BlockCopy(t, 0, okm, pos, toCopy);
            pos += toCopy;
            counter++;
        }

        CryptographicOperations.ZeroMemory(prk);
        CryptographicOperations.ZeroMemory(t);
        return okm;
    }

    private static byte[] Concat(params byte[][] arrays)
    {
        var total = 0;
        foreach (var a in arrays) total += a.Length;
        var r = new byte[total];
        var o = 0;
        foreach (var a in arrays) { Buffer.BlockCopy(a, 0, r, o, a.Length); o += a.Length; }
        return r;
    }
}
