using Cryptography.Service;

class Program
{
    static async Task Main(string[] args)
    {
        AESService.GenerateAESKeyFile();
        AESService.EncryptSensitiveData("melvin@swiftx.co", "EMUsername");
        AESService.EncryptSensitiveData("fLV9Yp8RoefH", "EMPassword");
        Console.WriteLine(AESService.DecryptSensitiveData("EMPassword"));
    }
}