using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace Saml.Token
{
    public class Saml2
    {
        private string samlString = default(String);
        private XmlDocument samlDoc = default(XmlDocument);
        private string certificateName = default(String);
        private string signaturePrefix = default(String);
        private string assertionXPath = "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion";

        #region Constructor & Properties
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
        public string Signature { get; set; }
        public XmlNamespaceManager samlNamespaceManager
        {
            get
            {
                try
                {
                    XmlNamespaceManager samlNamespaceMgr = new XmlNamespaceManager(samlDoc.NameTable);
                    samlNamespaceMgr.AddNamespace(signaturePrefix, "http://www.w3.org/2000/09/xmldsig#");
                    samlNamespaceMgr.AddNamespace("wst", "http://schemas.xmlsoap.org/ws/2005/02/trust");
                    samlNamespaceMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
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

        public Saml2(string samlString, string signaturePrefix, string certificateName)
        {
            this.samlString = samlString;
            this.signaturePrefix = signaturePrefix;
            this.certificateName = certificateName;
        } 
        #endregion

        #region Load
        public void Load()
        {
            Load(false);
        }

        public void Load(bool decodeBeforeLoad)
        {
            try
            {
                string token = string.Empty;
                if (decodeBeforeLoad)
                {
                    byte[] encodedBA = Convert.FromBase64String(this.samlString);
                    ASCIIEncoding characterEncoding = new ASCIIEncoding();
                    token = characterEncoding.GetString(encodedBA);
                }
                else token = this.samlString;
                this.samlDocument = new XmlDocument();
                this.samlDocument.PreserveWhitespace = false;
                this.samlDocument.LoadXml(token);
            }
            catch (Exception) { throw; }

        } 
        #endregion

        #region GetSignatureXmlNode & GetAssertionXmlDocument
        private XmlNode GetSignatureXmlNode()
        {
            return samlDocument.DocumentElement.SelectSingleNode(assertionXPath + "/" + signaturePrefix + ":Signature", samlNamespaceManager);
        }

        private XmlDocument GetAssertionXmlDocument()
        {
            try
            {
                XmlDocument docAssertion = new XmlDocument();
                XmlNode nodeAssertion = samlDocument.DocumentElement.SelectSingleNode(assertionXPath, samlNamespaceManager);
                docAssertion.LoadXml(nodeAssertion.OuterXml);
                return docAssertion;
            }
            catch (Exception)
            {
                throw;
            }
        } 
        #endregion

        #region ValidatingAssertionSignature
        public bool ValidatingAssertionSignature()
        {
            bool bValid = false;
            // Extract Assertion
            XmlDocument docAssertion = GetAssertionXmlDocument();

            // Validating Assertion Signature
            if (certificate == null) throw new Exception("Certificate not found!");
            try
            {
                XmlNode xmlNode = GetSignatureXmlNode();
                if (xmlNode == null)
                {
                    throw new Exception("Signature for 'Assertion' tag not found");
                }
                SamlSignedXml signedXml = new SamlSignedXml(docAssertion.DocumentElement, "ID");
                signedXml.LoadXml((XmlElement)xmlNode);

                bValid = signedXml.CheckSignature(certificate, true);


            }
            catch (Exception)
            {
                throw;
            }
            return bValid;
        } 
        #endregion

        #region CheckExpiryCondition
        public bool CheckExpiryCondition()
        {
            XmlDocument docAssertion = GetAssertionXmlDocument();

            // Check Expiry from 'Conditions' attributes "NotBefore" and "NotOnOrAfter"
            try
            {
                XmlElement el = (XmlElement)docAssertion.GetElementsByTagName("saml:Conditions")[0];
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
                dtNotBefore = dtNotBefore.AddMinutes(-3);
                dtNotOnOrAfter = dtNotOnOrAfter.AddMinutes(3);
                DateTime dtNow = DateTime.Now.ToUniversalTime();

                if (dtNow < dtNotBefore || dtNow >= dtNotOnOrAfter)
                {
                    return false;
                }
            }
            catch (Exception)
            {
                throw;
            }
            return true;
        } 
        #endregion

        #region GetUserInformation
        public NameValueCollection GetUserInformation()
        {
            NameValueCollection userInfo = new NameValueCollection();
            XmlDocument docAssertion = GetAssertionXmlDocument();

            try
            {
                foreach (XmlElement el in docAssertion.GetElementsByTagName("saml:Attribute"))
                {
                    XmlAttribute attr = el.Attributes["Name"];
                    if (attr != null)
                    {
                        string strAttrName = attr.Value.ToUpper();
                        userInfo[strAttrName] = el.InnerText;
                    }
                }
            }
            catch (Exception)
            {
                throw;
            }

            return userInfo;
        } 
        #endregion


    }

    
}
