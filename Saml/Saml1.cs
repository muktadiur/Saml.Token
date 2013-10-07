using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;

namespace Saml.Token
{
    public class Saml1
    {
        private string samlString = default(String);
        private XmlDocument samlDoc = default(XmlDocument);
        private string certificateName = default(String);
        private string signaturePrefix = default(String);

        public XmlDocument samlDocument
        {
            get
            {
                return samlDoc;
            }
            set
            {
                samlDoc = value;
            }
        }
        public XmlNamespaceManager samlNamespaceManager
        {
            get
            {
                try
                {
                    XmlNamespaceManager samlNamespaceMgr = new XmlNamespaceManager(samlDoc.NameTable);
                    samlNamespaceMgr.AddNamespace(signaturePrefix, "http://www.w3.org/2000/09/xmldsig#");
                    samlNamespaceMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:1.0:protocol");
                    samlNamespaceMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:1.0:assertion");
                    return samlNamespaceMgr;
                }
                catch (Exception ex) { throw ex; }
            }
        }
        public X509Certificate2 certificate
        {
            get
            {
                return Certificate.GetCertificate(this.certificateName);
            }
        }

        public Saml1(string samlString, string signaturePrefix, string certificateName)
        {
            this.samlString = samlString;
            this.signaturePrefix = signaturePrefix;
            this.certificateName = certificateName;
        }

        public void DecodeBase64()
        {
            try
            {
                byte[] encodedBA = Convert.FromBase64String(this.samlString);
                System.Text.ASCIIEncoding characterEncoding = new System.Text.ASCIIEncoding();
                string decodedData = characterEncoding.GetString(encodedBA);
                this.samlDocument = new XmlDocument();
                this.samlDocument.PreserveWhitespace = true;
                this.samlDocument.LoadXml(decodedData);
            }
            catch (Exception ex) { throw ex; }
        }

        public bool ValidateResponseSignature()
        {
            bool validationStatus = false;

            try
            {
                XmlNode xmlNode = samlDocument.DocumentElement.SelectSingleNode("/samlp:Response/" + signaturePrefix + ":Signature", samlNamespaceManager);
                if (xmlNode == null)
                {
                    throw new Exception("Signature for 'Response' tag not found.");
                }
                SamlSignedXml signedXml = new SamlSignedXml(samlDocument.DocumentElement, "ResponseID");
                signedXml.LoadXml((XmlElement)xmlNode);

                validationStatus = signedXml.CheckSignature(certificate, true);
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return validationStatus;
        }

        public bool ValidatingAssertionSignature()
        {
            bool bValid = false;
            // Extract Assertion
            XmlDocument docAssertion = new XmlDocument();
            try
            {
                XmlNode nodeAssertion = samlDocument.DocumentElement.SelectSingleNode("/samlp:Response/saml:Assertion", samlNamespaceManager);
                docAssertion.LoadXml(nodeAssertion.OuterXml);
            }
            catch (Exception ex)
            {
                throw ex; ;
            }

            // Validating Assertion Signature

            try
            {
                XmlNode xmlNode = docAssertion.DocumentElement.SelectSingleNode("/saml:Assertion/" + signaturePrefix + ":Signature", samlNamespaceManager);
                if (xmlNode == null)
                {
                    throw new Exception("Signature for 'Assertion' tag not found");
                }
                SamlSignedXml signedXml = new SamlSignedXml(docAssertion.DocumentElement, "AssertionID");
                signedXml.LoadXml((XmlElement)xmlNode);

                bValid = signedXml.CheckSignature(certificate, true);

                
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return bValid;
        }

        public bool CheckExpiryCondition()
        {
            XmlDocument docAssertion = new XmlDocument();
            try
            {
                XmlNode nodeAssertion = samlDocument.DocumentElement.SelectSingleNode("/samlp:Response/saml:Assertion", samlNamespaceManager);
                docAssertion.LoadXml(nodeAssertion.OuterXml);
            }
            catch (Exception ex)
            {
                throw ex; ;
            }
            // Check Expiry from 'Conditions' attributes "NotBefore" and "NotOnOrAfter"
            try
            {
                XmlElement el = (XmlElement)docAssertion.GetElementsByTagName("Conditions")[0];
                if (el == null)
                {
                    throw new Exception("SAML Assertion does not contain 'Conditions' tag");
                }
                string strNotBefore = el.Attributes["NotBefore"].Value;
                string strNotOnOrAfter = el.Attributes["NotOnOrAfter"].Value;
                if (strNotBefore.Length < 12 || !Char.IsDigit(strNotBefore[0]) || strNotOnOrAfter.Length < 12 || !Char.IsDigit(strNotOnOrAfter[0]))
                {
                    throw new Exception("Invalid 'NotBefore' or 'NotOnOrAfter' attribute value in 'Conditions' tag");
                }
                DateTime dtNotBefore, dtNotOnOrAfter;
                try
                {
                    dtNotBefore = DateTime.Parse(strNotBefore).ToUniversalTime();
                    dtNotOnOrAfter = DateTime.Parse(strNotOnOrAfter).ToUniversalTime();
                }
                catch (Exception ex)
                {
                    throw new Exception("Invalid 'NotBefore' or 'NotOnOrAfter' date in 'Conditions' tag: " + ex.Message);
                }
                //dtNotBefore = dtNotBefore.AddSeconds(-30);    // Add 2 x 30 seconds to interval, in case server times differ
                //dtNotOnOrAfter = dtNotOnOrAfter.AddSeconds(30);
                dtNotBefore = dtNotBefore.AddMinutes(-3);
                dtNotOnOrAfter = dtNotOnOrAfter.AddMinutes(3);
                DateTime dtNow = DateTime.Now.ToUniversalTime();

                if (dtNow < dtNotBefore || dtNow >= dtNotOnOrAfter)
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return true;
        }

        public NameValueCollection GetUserInformation()
        {
            NameValueCollection userInfo = new NameValueCollection();
            XmlDocument docAssertion = new XmlDocument();
            try
            {
                XmlNode nodeAssertion = samlDocument.DocumentElement.SelectSingleNode("/samlp:Response/saml:Assertion", samlNamespaceManager);
                docAssertion.LoadXml(nodeAssertion.OuterXml);
            }
            catch (Exception ex)
            {
                throw ex; ;
            }
            try
            {
                foreach (XmlElement el in docAssertion.GetElementsByTagName("Attribute"))
                {
                    XmlAttribute attr = el.Attributes["AttributeName"];
                    if (attr != null)
                    {
                        string strAttrName = attr.Value.ToUpper();
                        userInfo[strAttrName] =  el.InnerText;
                    }
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

            // Get UserID from 'Response' attribute "ResponseID"
            try
            {
                XmlElement el = (XmlElement)samlDocument.GetElementsByTagName("NameIdentifier")[0];
                if (el == null)
                {
                    throw new Exception("'NameIdentifier' tag not found in SAML token");
                }
                string attr = el.InnerText;
                if (attr == null)
                {
                    throw new Exception("'NameIdentifier' attribute not found in 'Response' tag");
                }
                userInfo["USER_ID"] = attr;
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return userInfo;
        }
    }

    
}
