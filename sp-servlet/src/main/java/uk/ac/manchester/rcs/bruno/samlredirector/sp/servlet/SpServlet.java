/**-----------------------------------------------------------------------
  
Copyright (c) 2009, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

  Author........: Bruno Harbulot

-----------------------------------------------------------------------*/
package uk.ac.manchester.rcs.bruno.samlredirector.sp.servlet;

import java.io.IOException;
import java.net.URI;
import java.security.PublicKey;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;

import uk.ac.manchester.rcs.bruno.samlredirector.sp.SamlAuthnRequestBuilder;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
@SuppressWarnings("serial")
public class SpServlet extends HttpServlet {
    public final static String IDPPUBKEY_JNDI_INITPARAM = "idppubkey";
    public final static String DEFAULT_IDPPUBKEY_JNDI_INITPARAM = "keystore/idpPublicKey";
    public final static String IDPURL_INITPARAM = "idpUrl";

    private PublicKey idpPublicKey;
    private String idpUrl;

    /**
     * Initialises the servlet with the public key of the IdP so that it can
     * verify the SAML assertions.
     */
    @Override
    public void init() throws ServletException {
        String idpUrl = getInitParameter(IDPURL_INITPARAM);
        String idppubkeyJdniName = getInitParameter(IDPPUBKEY_JNDI_INITPARAM);
        if (idppubkeyJdniName == null) {
            idppubkeyJdniName = DEFAULT_IDPPUBKEY_JNDI_INITPARAM;
        }
        PublicKey idpPublicKey = null;
        try {
            Context ctx = null;
            try {
                idpPublicKey = (PublicKey) new InitialContext().lookup("java:comp/env/"
                        + idppubkeyJdniName);

            } finally {
                if (ctx != null) {
                    ctx.close();
                }
            }
        } catch (NameNotFoundException e) {
        } catch (NamingException e) {
            throw new ServletException(e);
        }
        synchronized (this) {
            this.idpPublicKey = idpPublicKey;
            this.idpUrl = idpUrl;
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        /*
         * If there is a SAML response, then the user is comming back from the
         * Idp. Otherwise, generate the SAML request to make the user send to
         * the Idp.
         */
        String samlResponseParam = request.getParameter("SAMLResponse");
        if ((samlResponseParam != null) && (samlResponseParam.length() > 0)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            try {
                /*
                 * Reads the SAML response.
                 */
                BasicSAMLMessageContext<Response, SAMLObject, SAMLObject> msgContext = new BasicSAMLMessageContext<Response, SAMLObject, SAMLObject>();
                msgContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
                HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder() {
                    @SuppressWarnings("unchecked")
                    @Override
                    protected void checkEndpointURI(SAMLMessageContext messageContext)
                            throws SecurityException, MessageDecodingException {
                        // boolean destRequired =
                        // isIntendedDestinationEndpointURIRequired(messageContext);
                        // System.err
                        // .println("Binding requires destination endpoint? "
                        // + destRequired);
                        // System.err
                        // .println("Destination Endpoint: "
                        // + getIntendedDestinationEndpointURI(messageContext));
                    }
                };
                decoder.decode(msgContext);
                Response samlResponse = msgContext.getInboundSAMLMessage();
                if ((samlResponse == null) || (samlResponse.getAssertions() == null)
                        || (samlResponse.getAssertions().size() != 1)) {
                    return;
                }

                Assertion samlAssertion = samlResponse.getAssertions().get(0);
                if (samlAssertion == null) {
                    return;
                }

                /*
                 * Verify the signature with the (only) known public key.
                 */
                SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();
                signatureProfileValidator.validate(samlAssertion.getSignature());

                BasicCredential verifCredential = new BasicCredential();
                synchronized (this) {
                    verifCredential.setPublicKey(this.idpPublicKey);
                }
                SignatureValidator signatureValidator = new SignatureValidator(verifCredential);
                signatureValidator.validate(samlAssertion.getSignature());

                /*
                 * Checks the content of the assertion: audience, subject, time
                 * and authn-statement.
                 */
                if ((samlAssertion == null) || (samlAssertion.getSubject() == null)
                        || (samlAssertion.getSubject().getNameID() == null)
                        || (samlAssertion.getSubject().getNameID().getValue() == null)
                        || (samlAssertion.getSubject().getNameID().getValue().length() <= 0)
                        || (samlAssertion.getConditions() == null)
                        || (samlAssertion.getConditions().getAudienceRestrictions() == null)
                        || (samlAssertion.getConditions().getAudienceRestrictions().size() <= 0)
                        || (samlAssertion.getAuthnStatements() == null)
                        || (samlAssertion.getAuthnStatements().size() != 1)) {
                    return;
                }

                String spUri = new String(request.getRequestURL());
                boolean isTargetAudience = false;
                audienceRestrictions: for (AudienceRestriction audienceRestriction : samlAssertion
                        .getConditions().getAudienceRestrictions()) {
                    for (Audience audience : audienceRestriction.getAudiences()) {
                        if (spUri.equals(audience.getAudienceURI())) {
                            isTargetAudience = true;
                            break audienceRestrictions;
                        }
                    }
                }
                if (!isTargetAudience) {
                    return;
                }

                AuthnStatement samlAuthnStatement = samlAssertion.getAuthnStatements().get(0);
                if (samlAuthnStatement == null) {
                    return;
                }

                DateTime authnTime = samlAuthnStatement.getAuthnInstant();
                if (!authnTime.isBeforeNow()
                        && authnTime.isAfter(authnTime.minusSeconds(60).getMillis())) {
                    return;
                }

                /*
                 * Only display authenticated ID at the moment...
                 */
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("text/plain");
                response.getWriter().print(samlAssertion.getSubject().getNameID().getValue());
            } catch (MessageDecodingException e) {
                return;
            } catch (SecurityException e) {
                return;
            } catch (ValidationException e) {
                return;
            }

        } else {
            /*
             * Generate the SAML authentication request, to be sent to the IdP
             * by the user.
             */
            try {
                AuthnRequest authnRequest = SamlAuthnRequestBuilder.getInstance()
                        .buildAuthnRequest(URI.create(new String(request.getRequestURL())));

                BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> msgContext = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
                msgContext.setOutboundMessageTransport(new HttpServletResponseAdapter(response,
                        false));
                msgContext.setOutboundSAMLMessage(authnRequest);
                HTTPRedirectDeflateEncoder httpEncoder = new HTTPRedirectDeflateEncoder() {
                    @SuppressWarnings("unchecked")
                    @Override
                    protected String getEndpointURL(SAMLMessageContext messageContext)
                            throws MessageEncodingException {
                        synchronized (SpServlet.this) {
                            return SpServlet.this.idpUrl;
                        }
                    }
                };
                httpEncoder.encode(msgContext);
            } catch (MessageEncodingException e) {
                throw new RuntimeException("Error when encoding the response.", e);
            }
        }
    }
}
