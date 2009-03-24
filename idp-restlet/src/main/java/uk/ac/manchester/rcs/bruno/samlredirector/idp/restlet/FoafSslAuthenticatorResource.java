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
package uk.ac.manchester.rcs.bruno.samlredirector.idp.restlet;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import net.java.dev.sommer.foafssl.verifier.DereferencingFoafSslVerifier;
import net.java.dev.sommer.foafssl.verifier.FoafSslVerifier;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.restlet.Context;
import org.restlet.data.Request;
import org.restlet.data.Status;
import org.restlet.resource.Resource;

import uk.ac.manchester.rcs.bruno.samlredirector.idp.SamlAuthnResponseBuilder;
import uk.ac.manchester.rcs.bruno.samlredirector.misc.RestletRequestInTransportAdapter;
import uk.ac.manchester.rcs.bruno.samlredirector.misc.RestletResponseOutTransportAdapter;


/**
 * 
 * WORK IN PROGRESS, vastly unfinished / untested.
 * 
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class FoafSslAuthenticatorResource extends Resource {
	private static FoafSslVerifier FOAF_SSL_VERIFIER = new DereferencingFoafSslVerifier();

	public final static String SIGNING_CREDENTIAL_ATTRIBUTE = "uk.ac.manchester.rcs.bruno.samlredirector.attr_signing_cred";
	public final static String ISSUER_NAME_ATTRIBUTE = "uk.ac.manchester.rcs.bruno.samlredirector.attr_issuer_name";

	@Override
	public void init(Context context, Request request,
			org.restlet.data.Response response) {
		super.init(context, request, response);
		Collection<URI> verifiedWebIDs = null;

		@SuppressWarnings("unchecked")
		List<X509Certificate> certificates = (List<X509Certificate>) request
				.getAttributes().get("org.restlet.https.clientCertificates");
		if (certificates != null) {
			X509Certificate foafSslCertificate = certificates.get(0);
			try {
				verifiedWebIDs = FOAF_SSL_VERIFIER
						.verifyFoafSslCertificate(foafSslCertificate);
			} catch (Exception e) {
				getResponse().setStatus(Status.SERVER_ERROR_INTERNAL);
				throw new RuntimeException("Certificate verification failed.");
			}
		}

		if ((verifiedWebIDs != null) && (verifiedWebIDs.size() > 0)) {
			BasicSAMLMessageContext<AuthnRequest, Response, SAMLObject> msgContext = new BasicSAMLMessageContext<AuthnRequest, Response, SAMLObject>();
			msgContext
					.setInboundMessageTransport(new RestletRequestInTransportAdapter(
							request));

			HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();

			try {
				decoder.decode(msgContext);
				AuthnRequest authnRequest = msgContext.getInboundSAMLMessage();
				final String consumerServiceUrl = authnRequest
						.getAssertionConsumerServiceURL();

				URI webId = verifiedWebIDs.iterator().next();

				Credential signingCredential = (Credential) getContext()
						.getAttributes().get(SIGNING_CREDENTIAL_ATTRIBUTE);
				String issuerName = (String) getContext().getAttributes().get(
						ISSUER_NAME_ATTRIBUTE);
				Response samlResponse = SamlAuthnResponseBuilder.getInstance()
						.buildSubjectAuthenticatedAssertion(
								URI.create(issuerName), null, webId,
								signingCredential);

				msgContext
						.setOutboundMessageTransport(new RestletResponseOutTransportAdapter(
								response));
				msgContext.setOutboundSAMLMessage(samlResponse);

				HTTPRedirectDeflateEncoder httpEncoder = new HTTPRedirectDeflateEncoder() {
					@SuppressWarnings("unchecked")
					@Override
					protected String getEndpointURL(
							SAMLMessageContext messageContext)
							throws MessageEncodingException {
						return consumerServiceUrl;
					}
				};
				httpEncoder.encode(msgContext);
			} catch (MessageDecodingException e) {
				response.setStatus(Status.CLIENT_ERROR_BAD_REQUEST);
				throw new RuntimeException("Error when decoding the request.",
						e);
			} catch (SecurityException e) {
				response.setStatus(Status.CLIENT_ERROR_BAD_REQUEST);
				throw new RuntimeException("Error when decoding the request.",
						e);
			} catch (MessageEncodingException e) {
				throw new RuntimeException("Error when encoding the response.",
						e);
			}
		} else {
			response.setStatus(Status.CLIENT_ERROR_UNAUTHORIZED);
		}
	}
}
