namespace Gosuslugi.Auth;

public struct AuthData
{
    public string ResponseData { get; private set; }
    
    public string StateCode { get; private set; }

    internal AuthData(string data, string state)
    {
        ResponseData = data;
        StateCode = state;
    }
}