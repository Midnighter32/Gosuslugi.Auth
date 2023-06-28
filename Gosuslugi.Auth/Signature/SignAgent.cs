using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using LibCore;

namespace Gosuslugi.Auth.Signature;

internal class SignAgent : IDisposable
{
    private readonly X509Certificate2 _certificate;

    static SignAgent()
    {
        Initializer.Initialize(Initializer.DetouredAssembly.Pkcs);
    }
    
    private SignAgent(X509Certificate2 certificate)
    {
        _certificate = certificate;
    }

    private static X509Store OpenCertificateStore()
    {
        var certStore = new X509Store();
        certStore.Open(OpenFlags.ReadOnly);

        return certStore;
    }

    public string SignString(string inputString)
    {
        var dataToSign = Encoding.Default.GetBytes(inputString);

        var contentInfo = new ContentInfo(dataToSign);
        var signedCms = new SignedCms(contentInfo, false);
        var cmsSigner = new CmsSigner(_certificate);
        
        signedCms.ComputeSignature(cmsSigner);

        var signature = signedCms.Encode();

        return Convert.ToBase64String(signature);
    }

    public static SignAgent ByThumbprint(string thumbprint)
    {
        using var store = OpenCertificateStore();
        
        var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true);

        if (certificates.Count == 0)
            throw new ArgumentException("No certificates found for provided thumbprint", nameof(thumbprint));

        return new SignAgent(certificates.First());
    }

    public void Dispose()
    {
        _certificate.Dispose();
    }
}