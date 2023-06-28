using System.Text;
using System.Web;
using Gosuslugi.Auth.JsonModels;
using Gosuslugi.Auth.Signature;
using Newtonsoft.Json;

namespace Gosuslugi.Auth;

public class AuthAgent : IDisposable
{
    private const string RequiredHost = "esia.gosuslugi.ru";

    private static readonly IEnumerable<string> RequiredKeys = new[]
        { "client_id", "client_secret", "scope", "response_type", "state", "timestamp", "redirect_uri" };

    private readonly HttpClient _client;
    
    private string? State { get; set; }
    private string? ResponseType { get; set; }
    
    private AuthAgent()
    {
        _client = new HttpClient();
    }

    private async Task LoadCookieFromLink(Uri authLink)
    {
        if (authLink.Host != RequiredHost)
            throw new ArgumentException("The link must be to the ESIA website", nameof(authLink));
        
        var response = await _client.GetAsync(authLink);

        if (!response.IsSuccessStatusCode)
            throw new Exception($"Error during request to ESIA ({nameof(LoadCookieFromLink)})");
    }

    private async Task<string> GetChallengeNumber()
    {
        const string challengeRequest = "/aas/oauth2/api/login/digital/request";
        
        var response = await _client.GetAsync("https://" + RequiredHost + challengeRequest);
        
        if (!response.IsSuccessStatusCode)
            throw new Exception($"Error during request to ESIA ({nameof(GetChallengeNumber)})");

        var data = await response.Content.ReadAsStringAsync();
        
        var challenge = JsonConvert.DeserializeObject<DigitalChallenge>(data);

        return challenge.Number;
    }

    private string SolveChallenge(string thumbprint, string challengeNumber)
    {
        using var signature = SignAgent.ByThumbprint(thumbprint);
        
        return signature.SignString(challengeNumber);
    }

    private async Task<Uri> ValidateChallenge(string signedNumber)
    {
        const string validateRequest = "/aas/oauth2/api/login/digital/validate";
        
        var json = JsonConvert.SerializeObject(new
        {
            signature = signedNumber
        });
        var request = new StringContent(json, Encoding.UTF8, "application/json");
        
        var response = await _client.PostAsync("https://" + RequiredHost + validateRequest, request);
        
        if (!response.IsSuccessStatusCode)
            throw new Exception($"Error during request to ESIA ({nameof(ValidateChallenge)})");

        var data = await response.Content.ReadAsStringAsync();
        
        var redirect = JsonConvert.DeserializeObject<RedirectData>(data);
        
        if (redirect.Action != "DONE")
            throw new Exception($"Error during request to ESIA ({nameof(ValidateChallenge)}). Status: " + redirect.Action);

        return new Uri(redirect.Url);
    }

    public async Task<AuthData> Authorize(string thumbprint)
    {
        var number = await GetChallengeNumber();

        var signature = SolveChallenge(thumbprint, number);

        var redirectUri = await ValidateChallenge(signature);
        
        var query = HttpUtility.ParseQueryString(redirectUri.Query)
            ?? throw new Exception("Error when trying to parse arguments from a received link");

        var receivedState = query["state"]
            ?? throw new Exception("Received empty state code from ESIA");
        
        var responseData = query[ResponseType]
            ?? throw new Exception("Received empty response from ESIA");

        if (State != receivedState)
            throw new Exception("The status code received from ESIA does not match the one specified in the link");

        return new AuthData(responseData, receivedState);
    }

    public static async Task<AuthAgent> FromAuthLink(Uri authLink)
    {
        var esia = new AuthAgent();
        
        var query = HttpUtility.ParseQueryString(authLink.Query)
            ?? throw new ArgumentException("Error when trying to parse arguments from a link", nameof(authLink));

        if (!RequiredKeys.All(requiredKey => query.AllKeys.Any(key => key == requiredKey)))
            throw new ArgumentException("The link must contain all the required arguments. Required arguments: " +
                                        string.Join(", ", RequiredKeys));

        esia.State = query["state"]
            ?? throw new ArgumentException("State code cannot be empty", nameof(authLink));
        
        esia.ResponseType = query["response_type"]
            ?? throw new ArgumentException("Response type cannot be empty", nameof(authLink));

        await esia.LoadCookieFromLink(authLink);

        return esia;
    }

    public void Dispose()
    {
        _client.Dispose();
    }
}