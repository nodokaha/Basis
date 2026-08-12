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
                if (hasFileSupport)
                {
                    string configDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, configFolderName);
                    Directory.CreateDirectory(configDir);
                    string path = Path.Combine(configDir, FileName);

                    if (TryLoad(path, out string loadedId))
                    {
                        _serverId = loadedId;
                        BNL.Log($"Loaded Server ID {_serverId}");
                        return;
                    }

                    _serverId = GenerateDidKey();
                    File.WriteAllText(path, _serverId);
                    BNL.Log($"Generated new Server ID {_serverId}");
                    return;
                }

                _serverId = GenerateDidKey();
                BNL.LogWarning($"Generated temporary Server ID {_serverId}; file support is disabled so it cannot persist across restarts.");
            }
        }

        private static bool TryLoad(string path, out string serverId)
        {
            serverId = string.Empty;
            if (!File.Exists(path))
            {
                return false;
            }

            string loaded = File.ReadAllText(path).Trim();
            if (!loaded.StartsWith(DidKeyResolver.PREFIX, StringComparison.Ordinal))
            {
                BNL.LogWarning($"Ignoring invalid Server ID in {path}");
                return false;
            }

            serverId = loaded;
            return true;
        }

        private static string GenerateDidKey()
        {
            using CryptoRng rng = CryptoRng.Create();
            byte[] privateKeyBytes = new byte[Ed25519.PrivkeySize];
            rng.GetBytes(privateKeyBytes);
            PubKey pubKey = Ed25519.ConvertPrivkeyToPubkey(new PrivKey(privateKeyBytes))
                ?? throw new InvalidOperationException("Generated server DID private key was invalid.");
            Did did = DidKeyResolver.EncodePubkeyAsDid(pubKey);
            return did.V;
        }
    }
}
