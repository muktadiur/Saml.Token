using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.IO;

namespace Saml.Token
{
    public class SamlSignedXml : SignedXml
    {
        private string _referenceAttributeId = "";
        public string Path { get; set; }
        public SamlSignedXml(XmlElement element, string referenceAttributeId)
            : base(element)
        {
            _referenceAttributeId = referenceAttributeId;
        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            return (XmlElement)document.SelectSingleNode(string.Format("//*[@{0}='{1}']", _referenceAttributeId, idValue));
        }
        
    }
}
