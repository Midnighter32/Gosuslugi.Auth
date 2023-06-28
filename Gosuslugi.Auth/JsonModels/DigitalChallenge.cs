using Newtonsoft.Json;

namespace Gosuslugi.Auth.JsonModels;

struct DigitalChallenge
{
    [JsonProperty("digital_challenge")]
    public string Number { get; private set; }
};