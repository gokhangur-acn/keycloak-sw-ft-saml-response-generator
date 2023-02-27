package com.customization.keycloakAuthenticator;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.ws.rs.core.Response;
import java.io.IOException;

public class CustomSamlProtocol extends SamlProtocol {



    protected Response buildAuthenticatedResponse(AuthenticatedClientSessionModel clientSession, String redirectUri, Document samlDocument, JaxrsSAML2BindingBuilder bindingBuilder) throws ConfigurationException, ProcessingException, IOException {

//        // TODO use Keycloak provider information from this.session
        Element assertionElement = (Element) samlDocument.getElementsByTagNameNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(), "Assertion").item(0);
        final UserModel userModel = clientSession.getUserSession().getUser();

       Element attributeStatementElement = (Element) assertionElement.getElementsByTagNameNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(), "AttributeStatement").item(0);
       if (attributeStatementElement == null) {
           attributeStatementElement = samlDocument.createElementNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(), "AttributeStatement");
            assertionElement.appendChild(attributeStatementElement);
        }
        final Element embeddedXMLAsValue = createEmbededXMLAsValue(samlDocument, userModel);

        // TODO pull information from user attributes
       attributeStatementElement.appendChild(newSamlAttributeElement(samlDocument, null, "newAttribute", JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC.get(), embeddedXMLAsValue));


        return super.buildAuthenticatedResponse(clientSession, redirectUri, samlDocument, bindingBuilder);
    }


    private Element createEmbededXMLAsValue(Document samlDocument, final UserModel userModel) {
        Element authContextInfoElement = samlDocument.createElementNS("urn:swift:saml:Sw.01","AuthContextInfo");
        authContextInfoElement.setPrefix("Sw");

        Element netWorkElement = samlDocument.createElement("Network");
        netWorkElement.setTextContent(userModel.getAttributeStream("sw_network").findFirst().orElse(null));

        Element subjectDNElement = samlDocument.createElement("SubjectDN");
        subjectDNElement.setTextContent(userModel.getAttributeStream("sw_subjectdn").findFirst().orElse(null));

        Element policyOIDNElement = samlDocument.createElement("PolicyOID");
        policyOIDNElement.setTextContent("SWIFT_OID");

        authContextInfoElement.appendChild(netWorkElement);
        authContextInfoElement.appendChild(subjectDNElement);
        authContextInfoElement.appendChild(policyOIDNElement);

        return authContextInfoElement;


    }

    private Element newSamlAttributeElement(Document samlDocument, String friendlyName, String name, String nameFormat, Object value) {

        Element targetSamlAttributeElement = samlDocument.createElementNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(), "Attribute");

        if (friendlyName != null) {
            targetSamlAttributeElement.setAttribute("FriendlyName", friendlyName);
        }
        targetSamlAttributeElement.setAttribute("Name", name);
        if (nameFormat != null) {
            targetSamlAttributeElement.setAttribute("NameFormat", nameFormat);
        }
        targetSamlAttributeElement.setPrefix("saml");

        Element samlAttributeValue = samlDocument.createElementNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(), "AttributeValue");
        samlAttributeValue.setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
        samlAttributeValue.setPrefix("saml");

        targetSamlAttributeElement.appendChild(samlAttributeValue);

        if (value instanceof String) {
            samlAttributeValue.setTextContent((String) value);
        } else if (value instanceof Element) {
            samlAttributeValue.appendChild((Element) value);
        } else if (value != null) {
            samlAttributeValue.setTextContent(value.toString());
        } else {
            samlAttributeValue.setTextContent(String.valueOf(value));
        }

        return targetSamlAttributeElement;
    }


}