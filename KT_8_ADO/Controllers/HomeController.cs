using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

public class HomeController : Controller
{
    [HttpGet]
    public IActionResult Index() => View();

    [HttpPost]
    public IActionResult Index(string inputText, string algorithm, string key, string action)
    {
        string output = string.Empty;

        if (action == "encrypt")
            output = Encrypt(inputText, algorithm, key);
        else if (action == "decrypt")
            output = Decrypt(inputText, algorithm, key);

        ViewBag.InputText = inputText;
        ViewBag.OutputText = output;
        ViewBag.Algorithm = algorithm;
        ViewBag.Key = key;

        return View();
    }

    private string Encrypt(string text, string algorithm, string key)
    {
        if (algorithm == "AES")
        {
            using var aes = Aes.Create();
            aes.Key = string.IsNullOrEmpty(key) ? aes.Key : Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
            aes.GenerateIV();
            var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(text);
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            return Convert.ToBase64String(aes.IV.Concat(cipherBytes).ToArray());
        }
        else if (algorithm == "RSA")
        {
            using var rsa = RSA.Create();
            if (!string.IsNullOrEmpty(key))
                rsa.ImportRSAPublicKey(Convert.FromBase64String(key), out _);
            var cipher = rsa.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(cipher);
        }
        return null;
    }

    private static string Decrypt(string text, string algorithm, string key)
    {
        if (string.IsNullOrEmpty(text))
            return "Ошибка: текст";

        if(string.IsNullOrEmpty(key))
            return "Ошибка: ключ";

        if (algorithm == "AES")
        {
                // Проверяем, что длина ключа подходит
                using var aes = Aes.Create();
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32)); // проверяем ключ на 32 байта
                var fullCipher = Convert.FromBase64String(text);
                aes.IV = fullCipher.Take(16).ToArray(); // Первые 16 байт — это IV
                var cipher = fullCipher.Skip(16).ToArray(); // Остальные байты — это шифрованный текст

                using var decryptor = aes.CreateDecryptor();
                var plainBytes = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
                return Encoding.UTF8.GetString(plainBytes);
            
        }

        if (algorithm == "RSA")
        {            
                using var rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(key), out _); // Импортируем приватный ключ
                var cipherBytes = Convert.FromBase64String(text); // Декодируем зашифрованный текст

                var plainBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(plainBytes);

        }

        return "Ошибка: все не то";
    }

}