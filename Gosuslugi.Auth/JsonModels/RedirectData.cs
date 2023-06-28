using Newtonsoft.Json;

namespace Gosuslugi.Auth.JsonModels;

struct RedirectData
{
    [JsonProperty("action")]
    public string Action { get; private set; }
    
    [JsonProperty("redirect_url")]
    public string Url { get; private set; }
}