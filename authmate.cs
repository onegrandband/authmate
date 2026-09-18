using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MfaE2ee
{
    // Domain models
    public class MfaAccount
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string EncryptedSecret { get; set; } = "";
        public string SecretNonce { get; set; } = "";
        public string SecretTag { get; set; } = "";
        public int Digits { get; set; } = 6;
        public int PeriodSeconds { get; set; } = 30;
    }

    public class EncryptedVault
    {
        public List<MfaAccount> Accounts { get; set; } = new List<MfaAccount>();
        public string Salt { get; set; } = "";
        public string BackupCodesBlob { get; set; } = "";
        public string BackupCodesNonce { get; set; } = "";
        public string BackupCodesTag { get; set; } = "";
    }

    public class BackupCodeSet
    {
        public string AccountId { get; set; } = "";
        public List<string> Codes { get; set; } = new List<string>();
    }

    // Cryptographic helpers: AES-256-GCM (best-effort cross-platform using AesGcm on .NET 5+)
    public static class Crypto
    {
        public const int KeySize = 32;
        public const int NonceSize = 12;
        public const int TagSize = 16;
        public const int SaltSize = 32;

        public static byte[] GenerateRandom(int bytes)
        {
            byte[] data = new byte[bytes];
            RandomNumberGenerator.Fill(data);
            return data;
        }

        public static byte[] DeriveKey(string password, byte[] salt)
        {
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(KeySize);
            }
        }

        public static bool AesGcmSupported()
        {
            try
            {
                using (AesGcm aes = new AesGcm(new byte[KeySize]))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public static void Encrypt(byte[] key, byte[] plaintext, out byte[] cipher, out byte[] nonce, out byte[] tag)
        {
            if (!AesGcmSupported())
                throw new PlatformNotSupportedException("AES-GCM is not available on this runtime. Use Windows with .NET 5+ or a compatible platform.");

            nonce = GenerateRandom(NonceSize);
            tag = new byte[TagSize];
            cipher = new byte[plaintext.Length];

            using (AesGcm aes = new AesGcm(key))
            {
                aes.Encrypt(nonce, plaintext, cipher, tag);
            }
        }

        public static byte[] Decrypt(byte[] key, byte[] cipher, byte[] nonce, byte[] tag)
        {
            if (!AesGcmSupported())
                throw new PlatformNotSupportedException("AES-GCM is not available on this runtime.");

            byte[] plaintext = new byte[cipher.Length];
            using (AesGcm aes = new AesGcm(key))
            {
                aes.Decrypt(nonce, cipher, tag, plaintext);
            }
            return plaintext;
        }
    }

    // RFC 6238 TOTP implementation
    public static class Totp
    {
        public static string GenerateCode(byte[] secret, int digits, int period, long timestamp)
        {
            long counter = timestamp / period;
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(counterBytes);

            byte[] key = Base32Decode(secret);
            using (HMACSHA1 hmac = new HMACSHA1(key))
            {
                byte[] hash = hmac.ComputeHash(counterBytes);

                int offset = hash[hash.Length - 1] & 0x0F;
                int binary = ((hash[offset] & 0x7F) << 24)
                           | ((hash[offset + 1] & 0xFF) << 16)
                           | ((hash[offset + 2] & 0xFF) << 8)
                           | (hash[offset + 3] & 0xFF);

                int code = binary % (int)Math.Pow(10, digits);
                return code.ToString().PadLeft(digits, '0');
            }
        }

        public static byte[] Base32Decode(byte[] base32)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            List<bool> bits = new List<bool>();
            foreach (byte b in base32)
            {
                char c = (char)b;
                if (c == '=')
                    continue;
                int index = alphabet.IndexOf(char.ToUpperInvariant(c));
                if (index < 0)
                    throw new FormatException("Invalid Base32 character: " + c);
                for (int i = 4; i >= 0; i--)
                    bits.Add((index & (1 << i)) != 0);
            }

            List<byte> bytes = new List<byte>();
            for (int i = 0; i < bits.Count; i += 8)
            {
                if (i + 8 > bits.Count)
                    break;
                byte value = 0;
                for (int j = 0; j < 8; j++)
                    value = (byte)((value << 1) | (bits[i + j] ? 1 : 0));
                bytes.Add(value);
            }
            return bytes.ToArray();
        }
    }

    public class MfaService
    {
        private readonly string _vaultPath;
        private EncryptedVault _vault;
        private byte[] _key;

        public MfaService(string vaultPath)
        {
            _vaultPath = vaultPath;
            _vault = new EncryptedVault();
        }

        public bool VaultExists
        {
            get { return File.Exists(_vaultPath); }
        }

        public bool IsUnlocked
        {
            get { return _key != null; }
        }

        public void CreateVault(string password)
        {
            byte[] salt = Crypto.GenerateRandom(Crypto.SaltSize);
            _key = Crypto.DeriveKey(password, salt);
            _vault = new EncryptedVault { Salt = Convert.ToBase64String(salt) };
            Save();
        }

        public bool TryUnlock(string password)
        {
            if (!VaultExists)
                return false;
            try
            {
                string json = File.ReadAllText(_vaultPath);
                _vault = JsonSerializer.Deserialize<EncryptedVault>(json);
                byte[] salt = Convert.FromBase64String(_vault.Salt);
                _key = Crypto.DeriveKey(password, salt);

                if (!string.IsNullOrEmpty(_vault.BackupCodesBlob))
                {
                    DecryptBackupCodes();
                }
                return true;
            }
            catch
            {
                _key = null;
                return false;
            }
        }

        public void Unlock(string password)
        {
            if (!TryUnlock(password))
                throw new InvalidOperationException("Vault does not exist or password is incorrect.");
        }

        public void Save()
        {
            string json = JsonSerializer.Serialize(_vault, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_vaultPath, json);
        }

        public void AddAccount(string name, string issuer, string base32Secret, int digits, int period)
        {
            EnsureUnlocked();
            byte[] secretBytes = Encoding.UTF8.GetBytes(base32Secret);
            byte[] cipher;
            byte[] nonce;
            byte[] tag;
            Crypto.Encrypt(_key, secretBytes, out cipher, out nonce, out tag);

            MfaAccount account = new MfaAccount
            {
                Name = name,
                Issuer = issuer,
                EncryptedSecret = Convert.ToBase64String(cipher),
                SecretNonce = Convert.ToBase64String(nonce),
                SecretTag = Convert.ToBase64String(tag),
                Digits = digits,
                PeriodSeconds = period
            };

            GenerateAndEncryptBackupCodes(account.Id);
            _vault.Accounts.Add(account);
            Save();
        }

        public void DeleteAccount(string id)
        {
            EnsureUnlocked();
            _vault.Accounts.RemoveAll(a => a.Id == id);
            Save();
        }

        public List<MfaAccount> ListAccounts()
        {
            EnsureUnlocked();
            return _vault.Accounts.ToList();
        }

        public string GenerateCode(string accountId, long? timestamp)
        {
            EnsureUnlocked();
            MfaAccount account = _vault.Accounts.FirstOrDefault(a => a.Id == accountId);
            if (account == null)
                throw new ArgumentException("Account not found.");

            byte[] cipher = Convert.FromBase64String(account.EncryptedSecret);
            byte[] nonce = Convert.FromBase64String(account.SecretNonce);
            byte[] tag = Convert.FromBase64String(account.SecretTag);
            byte[] secretBytes = Crypto.Decrypt(_key, cipher, nonce, tag);

            long ts = timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return Totp.GenerateCode(secretBytes, account.Digits, account.PeriodSeconds, ts);
        }

        public List<string> GetBackupCodes(string accountId)
        {
            EnsureUnlocked();
            List<BackupCodeSet> sets = DecryptBackupCodes();
            BackupCodeSet set = sets.FirstOrDefault(s => s.AccountId == accountId);
            if (set == null)
                return new List<string>();
            return set.Codes.ToList();
        }

        private void GenerateAndEncryptBackupCodes(string accountId)
        {
            List<BackupCodeSet> sets = string.IsNullOrEmpty(_vault.BackupCodesBlob)
                ? new List<BackupCodeSet>()
                : DecryptBackupCodes();

            List<string> codes = new List<string>();
            for (int i = 0; i < 10; i++)
            {
                byte[] bytes = Crypto.GenerateRandom(4);
                uint val = BitConverter.ToUInt32(bytes, 0);
                codes.Add(val.ToString("D8"));
            }
            sets.Add(new BackupCodeSet { AccountId = accountId, Codes = codes });
            EncryptBackupCodes(sets);
        }

        private List<BackupCodeSet> DecryptBackupCodes()
        {
            byte[] cipher = Convert.FromBase64String(_vault.BackupCodesBlob);
            byte[] nonce = Convert.FromBase64String(_vault.BackupCodesNonce);
            byte[] tag = Convert.FromBase64String(_vault.BackupCodesTag);
            byte[] json = Crypto.Decrypt(_key, cipher, nonce, tag);
            return JsonSerializer.Deserialize<List<BackupCodeSet>>(Encoding.UTF8.GetString(json));
        }

        private void EncryptBackupCodes(List<BackupCodeSet> sets)
        {
            byte[] json = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(sets));
            byte[] cipher;
            byte[] nonce;
            byte[] tag;
            Crypto.Encrypt(_key, json, out cipher, out nonce, out tag);
            _vault.BackupCodesBlob = Convert.ToBase64String(cipher);
            _vault.BackupCodesNonce = Convert.ToBase64String(nonce);
            _vault.BackupCodesTag = Convert.ToBase64String(tag);
        }

        private void EnsureUnlocked()
        {
            if (_key == null)
                throw new InvalidOperationException("Vault is locked. Unlock it first.");
        }
    }
}
