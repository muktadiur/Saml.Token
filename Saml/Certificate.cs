using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace Saml.Token
{
    public class Certificate
    {
        public static X509Certificate2 GetCertificate(string certificateName)
        {
            X509Store certificateStore;
            X509Certificate2Collection certificateCollection;

            try
            {
                certificateStore = new X509Store(StoreLocation.LocalMachine);
                certificateStore.Open(OpenFlags.ReadOnly);
                certificateCollection = certificateStore.Certificates;
            }
            catch (Exception ex) { throw ex; }

            foreach (X509Certificate2 certificate in certificateCollection)
            {
                if (certificate.Subject.Contains(certificateName))
                {
                    certificateStore.Close();
                    return certificate;
                }
            }

            return null;
        }
    }
}
