# Gosuslugi.Auth
A simple library for authorization in some services through esia.gosuslugi.ru

## Requirments
In this project, for signing with GOST certificates, the [CryptoPro LibCore package](https://github.com/CryptoPro/libcore) is used.

# Usage
``` c#
using System;
using Gosuslugi.Auth;

namespace ConsoleApp
{
    internal class Program
    {
        private static async Task Main(string[] args)
        {
            const string thumbprint = "0123456789ABCDF0123456789ABCDF012345678A";
        
            //https://esia.gosuslugi.ru/aas/oauth2/ac?args
            //Args: client_id, client_secret, scope, response_type, 
            //state, access_type, timestamp, redirect_uri
            var url = args[0];
        
            using var esia = await AuthAgent.FromAuthLink(url);
        
            var authData = await esia.Authorize(thumbprint);
            
            Console.WriteLine("Response: " + authData.ResponseData);
            Console.WriteLine("Status: " + authData.StatusCode);
        }
    }
}
```
