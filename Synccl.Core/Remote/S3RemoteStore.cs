using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Synccl.Core.Diff;
using Synccl.Core.Errors;
using Synccl.Core.Vault;
using System.Text;
using System.Text.Json;
using static Synccl.Core.Diff.SecretDiffEngine;

namespace Synccl.Core.Remote;

public sealed class S3RemoteStore : IRemoteStore
{
    private readonly IAmazonS3 _s3;
    private readonly string _bucket;
    private readonly string _key;
    private readonly IVaultService _localVaultService;

    public S3RemoteStore(string bucket, string key, string region, IVaultService localVaultService, string? profile = null)
    {
        if (!string.IsNullOrWhiteSpace(profile))
        {
            var chain = new Amazon.Runtime.CredentialManagement.CredentialProfileStoreChain();
            if (chain.TryGetAWSCredentials(profile, out var creds))
                _s3 = new AmazonS3Client(creds, RegionEndpoint.GetBySystemName(region));
            else
                throw new InvalidOperationException($"AWS profile '{profile}' not found.");
        }
        else
        {
            _s3 = new AmazonS3Client(RegionEndpoint.GetBySystemName(region));
        }

        _bucket = bucket;
        _key = key;
        _localVaultService = localVaultService;
    }

    // ---------------------------------------------------------------------
    // Remote vault helper
    // ---------------------------------------------------------------------

    private async Task<ServiceResponse<VaultModel>> TryDownloadRemoteVault()
    {
        try
        {
            using var mem = new MemoryStream();
            var obj = await _s3.GetObjectAsync(_bucket, _key);
            await obj.ResponseStream.CopyToAsync(mem);

            mem.Position = 0;
            var vault = JsonSerializer.Deserialize<VaultModel>(mem);
            if (vault != null)
                return ServiceResponse<VaultModel>.Ok(vault);
            else
                return ServiceResponse<VaultModel>.Fail("Failed to deserialize remote vault.");
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return ServiceResponse<VaultModel>.Fail("Remote vault not found.");
        }
    }

    // ---------------------------------------------------------------------
    // Exists
    // ---------------------------------------------------------------------

    public async Task<bool> Exists()
    {
        try
        {
            await _s3.GetObjectMetadataAsync(_bucket, _key);
            return true;
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    // ---------------------------------------------------------------------
    // DIFF
    // ---------------------------------------------------------------------

    public async Task<ServiceResponse<DiffResult>> DiffAsync(string root, string localNs, string remoteNs)
    {
        var localVaultResult = _localVaultService.LoadVault();
        if (localVaultResult.IsFailure)
            return ServiceResponse<DiffResult>.Fail(localVaultResult.ErrorMessage!);
        var localVault = localVaultResult.Data!;

        var remoteVaultResult = await TryDownloadRemoteVault();
        if (remoteVaultResult.IsFailure && remoteVaultResult.ErrorMessage != "Remote vault not found.")
            return ServiceResponse<DiffResult>.Fail(remoteVaultResult.ErrorMessage!);
        var remoteVault = remoteVaultResult.Data;

        if (remoteVault == null)
        {
            var localPlainResult = _localVaultService.ExportPlaintext(localVault, localNs);
            if (localPlainResult.IsFailure)
                return ServiceResponse<DiffResult>.Fail(localPlainResult.ErrorMessage!);
            var localPlain = localPlainResult.Data!;
            return ServiceResponse<DiffResult>.Ok(SecretDiffEngine.Compare(localPlain, new Dictionary<string, string>()));
        }

        var localPlaintextResult = _localVaultService.ExportPlaintext(localVault, localNs);
        if (localPlaintextResult.IsFailure)
            return ServiceResponse<DiffResult>.Fail(localPlaintextResult.ErrorMessage!);
        var localPlaintext = localPlaintextResult.Data!;

        var remotePlaintextResult = _localVaultService.ExportPlaintext(remoteVault, remoteNs);
        if (remotePlaintextResult.IsFailure)
            return ServiceResponse<DiffResult>.Fail(remotePlaintextResult.ErrorMessage!);
        var remotePlaintext = remotePlaintextResult.Data!;

        return ServiceResponse<DiffResult>.Ok(SecretDiffEngine.Compare(localPlaintext, remotePlaintext));
    }

    // ---------------------------------------------------------------------
    // PUSH
    // ---------------------------------------------------------------------

    public async Task<ServiceResponse> PushAsync(string root, string localNs, string remoteNs, ChangeApplicationMode mode)
    {
        var localVaultResult = _localVaultService.LoadVault();
        if (localVaultResult.IsFailure)
            return ServiceResponse.Fail(localVaultResult.ErrorMessage!);
        var localVault = localVaultResult.Data!;

        var remoteVaultResult = await TryDownloadRemoteVault();
        if (remoteVaultResult.IsFailure && remoteVaultResult.ErrorMessage != "Remote vault not found.")
            return ServiceResponse.Fail(remoteVaultResult.ErrorMessage!);

        var remoteVault = remoteVaultResult.Data
            ?? new VaultModel
            {
                Id = localVault.Id,
                WrappedVaultKeys = new(localVault.WrappedVaultKeys),
                Namespaces = new()
            };

        var localPlainResult = _localVaultService.ExportPlaintext(localVault, localNs);
        if (localPlainResult.IsFailure)
            return ServiceResponse.Fail(localPlainResult.ErrorMessage!);
        var localPlain = localPlainResult.Data!;

        var remotePlainResult = remoteVault.Namespaces.Any(n => n.Name == remoteNs)
            ? _localVaultService.ExportPlaintext(remoteVault, remoteNs)
            : ServiceResponse<Dictionary<string, string>>.Ok(new Dictionary<string, string>());

        if (remotePlainResult.IsFailure)
            return ServiceResponse.Fail(remotePlainResult.ErrorMessage!);
        var remotePlain = remotePlainResult.Data!;

        var diff = SecretDiffEngine.Compare(localPlain, remotePlain);
        var merged = SecretDiffEngine.ApplyDiff(diff, localPlain, remotePlain, mode);

        var importResult = _localVaultService.ImportPlaintext(remoteVault, merged, remoteNs);
        if (importResult.IsFailure)
            return ServiceResponse.Fail(importResult.ErrorMessage!);

        var json = JsonSerializer.Serialize(remoteVault, new JsonSerializerOptions { WriteIndented = true });
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));

        await _s3.PutObjectAsync(new PutObjectRequest
        {
            BucketName = _bucket,
            Key = _key,
            InputStream = stream
        });

        return diff.Changes.Any(c => c.Type != SecretChangeType.NoChange)
            ? ServiceResponse.Ok()
            : ServiceResponse.Fail("No changes to push.");
    }

    // ---------------------------------------------------------------------
    // PULL
    // ---------------------------------------------------------------------

    public async Task<ServiceResponse> PullAsync(string root, string localNs, string remoteNs, ChangeApplicationMode mode)
    {
        var localVaultResult = _localVaultService.LoadVault();
        if (localVaultResult.IsFailure)
            return ServiceResponse.Fail(localVaultResult.ErrorMessage!);
        var localVault = localVaultResult.Data!;

        var remoteVaultResult = await TryDownloadRemoteVault();
        if (remoteVaultResult.IsFailure)
            return ServiceResponse.Fail(remoteVaultResult.ErrorMessage!);
        var remoteVault = remoteVaultResult.Data!;

        var localPlainResult = _localVaultService.ExportPlaintext(localVault, localNs);
        if (localPlainResult.IsFailure)
            return ServiceResponse.Fail(localPlainResult.ErrorMessage!);
        var localPlain = localPlainResult.Data!;

        var remotePlainResult = _localVaultService.ExportPlaintext(remoteVault, remoteNs);
        if (remotePlainResult.IsFailure)
            return ServiceResponse.Fail(remotePlainResult.ErrorMessage!);
        var remotePlain = remotePlainResult.Data!;

        var diff = SecretDiffEngine.Compare(remotePlain, localPlain);
        var merged = SecretDiffEngine.ApplyDiff(diff, remotePlain, localPlain, mode);

        _localVaultService.ImportPlaintext(localVault, merged, localNs);
        _localVaultService.Save(localVault);
        return diff.Changes.Any(c => c.Type != SecretChangeType.NoChange) 
            ? ServiceResponse.Ok() 
            : ServiceResponse.Fail("No changes to pull.");
    }

    // ---------------------------------------------------------------------
    // GET HASH
    // ---------------------------------------------------------------------

    public async Task<string?> GetHash()
    {
        try
        {
            var meta = await _s3.GetObjectMetadataAsync(_bucket, _key);
            return meta.ETag?.Trim('"');
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }
}
