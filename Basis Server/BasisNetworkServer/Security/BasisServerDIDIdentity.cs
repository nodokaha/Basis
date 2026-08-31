using Basis.Contrib.Auth.DecentralizedIds;
using Basis.Contrib.Auth.DecentralizedIds.Newtypes;
using Basis.Contrib.Crypto;
using Basis.Network.Core;
using System;
using System.IO;
using CryptoRng = System.Security.Cryptography.RandomNumberGenerator;

namespace BasisNetworkServer.Security
{
    /// <summary>
    /// Owns the stable server DID. The identifier is generated once from an Ed25519 did:key
    /// keypair and persisted so reconnecting clients can recognize the same server after restarts.
    /// </summary>
    public static class BasisServerDIDIdentity
    {
        private const string FileName = "server.didkey";
        private static readonly object Sync = new object();
        private static string _serverId = string.Empty;

        public static string ServerId => _serverId;

        public static void Initialize(bool hasFileSupport, string configFolderName)
        {
            lock (Sync)
            {
                if (!string.IsNullOrEmpty(_serverId))
                {
                    return;
                }

                if (!hasFileSupport)
                {
                    _serverId = GenerateDidKey();
                    BNL.LogWarning("Generated a temporary Server ID because file support is disabled. It will not survive a process restart.");
                    return;
                }

                string path = GetIdentityPath(configFolderName);
                if (TryLoad(path, out string loadedId))
                {
                    _serverId = loadedId;
                    BNL.Log("Loaded persistent Server ID.");
                    return;
                }

                _serverId = GenerateDidKey();
                Save(path, _serverId);
                BNL.Log("Generated and saved persistent Server ID.");
            }
        }

        private static string GetIdentityPath(string configFolderName)
        {
            string configDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, configFolderName);
            Directory.CreateDirectory(configDir);
            return Path.Combine(configDir, FileName);
        }

        private static bool TryLoad(string path, out string serverId)
        {
            serverId = string.Empty;
            if (!File.Exists(path))
            {
                return false;
            }

            string loaded;
            try
            {
                loaded = File.ReadAllText(path).Trim();
            }
            catch (IOException exception)
            {
                BNL.LogWarning($"Could not read Server ID from {path}: {exception.Message}");
                return false;
            }

            if (!IsValidDidKey(loaded))
            {
                BNL.LogWarning($"Ignoring invalid Server ID in {path}");
                return false;
            }

            serverId = loaded;
            return true;
        }

        private static void Save(string path, string serverId)
        {
            string temporaryPath = path + ".tmp";
            File.WriteAllText(temporaryPath, serverId);

            if (File.Exists(path))
            {
                File.Replace(temporaryPath, path, null);
                return;
            }

            File.Move(temporaryPath, path);
        }

        internal static bool IsValidDidKey(string serverId)
        {
            if (!serverId.StartsWith(DidKeyResolver.PREFIX, StringComparison.Ordinal))
            {
                return false;
            }

            try
            {
                DidKeyResolver resolver = new DidKeyResolver();
                resolver.ResolveDocument(new Did(serverId)).GetAwaiter().GetResult();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        internal static string GenerateDidKey()
        {
            using CryptoRng rng = CryptoRng.Create();
            byte[] privateKeyBytes = new byte[Ed25519.PrivkeySize];
            rng.GetBytes(privateKeyBytes);
            PubKey pubKey = Ed25519.ConvertPrivkeyToPubkey(new PrivKey(privateKeyBytes))
                ?? throw new InvalidOperationException("Generated server DID private key was invalid.");
            return DidKeyResolver.EncodePubkeyAsDid(pubKey).V;
        }
    }
}
