using System.Text;
using Gosuslugi.Auth;
using Newtonsoft.Json;

namespace Fgis.Zerno.Auth;
// 1. https://zerno.mcx.gov.ru/api/esia/authorize                      -   Get a link to Gosuslugi
// 2. Load Session data and other cookies from received link
// 3. https://esia.gosuslugi.ru/aas/oauth2/api/login/digital/request   -   Get Challenge Number
// 4. Create attached digital signature of challenge number using CMS
// 5. https://esia.gosuslugi.ru/aas/oauth2/api/login/digital/validate  -   Validate Signature
// 6. Parse redirect link from response to get code and state
// 7. https://zerno.mcx.gov.ru/api/esia/callback                       -   Use the code and state to authorize in the service

struct AuthData
{
    [JsonProperty("accessToken")]
    public string Access { get; set; }
    
    [JsonProperty("refreshToken")]
    public string Refresh { get; set; }
}

internal static class Program
{
    private static async Task<Uri> GetEsiaLink()
    {
        using var client = new HttpClient();
        
        var url = await client.GetStringAsync("https://zerno.mcx.gov.ru/api/esia/authorize");
        
        return new Uri(url);
    }

    public static async Task Main(string[] args)
    {
        const string thumbprint = "5f96d07657f198d801b4cb3266497314a34df72b";

        var url = await GetEsiaLink();

        using var esia = await AuthAgent.FromAuthLink(url);
        
        var authData = await esia.Authorize(thumbprint);

        var auth = await Authorize(authData.ResponseData, authData.StateCode);
        
        Console.WriteLine("Refresh: " + auth.Refresh);
        Console.WriteLine("Access: " + auth.Access);
    }

    private static async Task<AuthData> Authorize(string code, string state)
    {
        using var client = new HttpClient();
        
        var json = JsonConvert.SerializeObject(new
        {
            code,
            state
        });
        var request = new StringContent(json, Encoding.UTF8, "application/json");
        
        var response = await client.PostAsync("https://zerno.mcx.gov.ru/api/esia/callback", request);

        var data = await response.Content.ReadAsStringAsync();
        
        var redirect = JsonConvert.DeserializeObject<AuthData>(data);

        return redirect;
    }
}
