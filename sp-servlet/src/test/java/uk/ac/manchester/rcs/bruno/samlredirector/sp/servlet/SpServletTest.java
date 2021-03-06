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

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.testing.HttpTester;
import org.mortbay.jetty.testing.ServletTester;
import org.restlet.data.Reference;

import uk.ac.manchester.rcs.bruno.samlredirector.idp.servlet.IdpServlet;
import uk.ac.manchester.rcs.bruno.samlredirector.sp.servlet.SpServletTest;
import uk.ac.manchester.rcs.bruno.samlredirector.sp.servlet.SpServlet;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class SpServletTest {

    public final static String CERTIFICATES_DIRECTORY = "org/jsslutils/certificates/";
    public final static String KEYSTORE_PASSWORD_STRING = "testtest";
    public final static char[] KEYSTORE_PASSWORD = KEYSTORE_PASSWORD_STRING.toCharArray();

    private static final String TEST_IDP_KEYNAME = "http://idp.example.org/idp/#pubkey";
    private static final String TEST_IDP_URI = "http://idp.example.org/idp/";
    private static final String TEST_SP_URI = "http://sp.example.com/sp/";

    public static final String TEST_BRUNO_FOAF_FILENAME = "dummy-foaf.rdf.xml";
    public static final String TEST_BRUNO_CERT_FILENAME = "dummy-foafsslcert.pem";
    public static final String TEST_BRUNO_FOAF_ID = "http://foaf.example.net/bruno#me";

    private ServletTester spServletTester;
    private ServletTester idpServletTester;

    /**
     * Loads the 'localhost' keystore from the test keystore.
     * 
     * @return test keystore.
     * @throws Exception
     */
    public KeyStore getKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream ksis = ClassLoader.getSystemResourceAsStream(CERTIFICATES_DIRECTORY
                + "localhost.p12");
        ks.load(ksis, KEYSTORE_PASSWORD);
        ksis.close();
        return ks;
    }

    /**
     * Returns the public key matching the private key used to sign the
     * assertion.
     * 
     * @return public key matching the private key used to sign the assertion.
     * @throws Exception
     */
    public PublicKey getPublicKey() throws Exception {
        KeyStore keyStore = getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return keyStore.getCertificate(alias).getPublicKey();
            }
        }
        return null;
    }

    /**
     * Sets up the servlet tester, loads the keystore and passes the appropriate
     * parameters.
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        /*
         * Passes the keystore via JNDI to the servlet.
         */
        Context ctx = null;

        try {
            Properties props = new Properties();
            props.setProperty(Context.INITIAL_CONTEXT_FACTORY,
                    "org.mortbay.naming.InitialContextFactory");
            ctx = (Context) new InitialContext(props).lookup("java:comp");
            try {
                ctx = (Context) ctx.lookup("env");
            } catch (NameNotFoundException e) {
                ctx = ctx.createSubcontext("env");
            }
            try {
                ctx = (Context) ctx.lookup("keystore");
            } catch (NameNotFoundException e) {
                ctx = ctx.createSubcontext("keystore");
            }
            ctx.rebind("idpPublicKey", getPublicKey());
            ctx.rebind("signingKeyStore", getKeyStore());
        } finally {
            if (ctx != null) {
                ctx.close();
            }
        }

        /*
         * Creates a mock URLConnection not to make outside connections to
         * de-reference the FOAF file for the tests.
         */
        URLStreamHandlerFactory mockStreamHandlerFactory = new URLStreamHandlerFactory() {
            @Override
            public URLStreamHandler createURLStreamHandler(String protocol) {
                if ("http".equals(protocol) || "https".equals(protocol)) {
                    return new URLStreamHandler() {
                        @Override
                        protected URLConnection openConnection(URL u) throws IOException {
                            return new HttpURLConnection(u) {
                                @Override
                                public void disconnect() {
                                }

                                @Override
                                public boolean usingProxy() {
                                    return false;
                                }

                                @Override
                                public void connect() throws IOException {
                                }

                                @Override
                                public String getContentType() {
                                    return "application/rdf+xml";
                                }

                                @Override
                                public InputStream getInputStream() throws IOException {
                                    return SpServletTest.class
                                            .getResourceAsStream(TEST_BRUNO_FOAF_FILENAME);
                                }
                            };
                        }
                    };
                }
                return null;
            }
        };
        try {
            URL.setURLStreamHandlerFactory(mockStreamHandlerFactory);
        } catch (Throwable e) {
        }

        /*
         * Creates the servlet testers.
         */
        spServletTester = new ServletTester();
        spServletTester.setContextPath("/sp");
        ServletHolder spServletHolder = spServletTester.addServlet(SpServlet.class, "/*");
        spServletHolder.setInitParameter("idpUrl", TEST_IDP_URI);
        spServletTester.start();

        idpServletTester = new ServletTester();
        idpServletTester.setContextPath("/idp");
        ServletHolder idpServletHolder = idpServletTester.addServlet(IdpServlet.class, "/*");
        idpServletHolder.setInitParameter("keyPassword", KEYSTORE_PASSWORD_STRING);
        idpServletHolder.setInitParameter("issuerName", TEST_IDP_URI);
        idpServletHolder.setInitParameter("keyName", TEST_IDP_KEYNAME);
        idpServletTester.addFilter(FakeClientCertInsertionFilter.class, "/*", 0);
        idpServletTester.start();
    }

    /**
     * Performs the initial request and gets the redirection
     * 
     * @return Reference to the Location in the response header.
     * @throws Throwable
     */
    public Reference doInitialRedirect() throws Throwable {
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        Reference resourceRef = new Reference(TEST_SP_URI);
        request.setHeader("Host", resourceRef.getHostDomain());
        request.setMethod("GET");
        String query = resourceRef.getQuery();
        request.setURI(resourceRef.getPath() + (query != null ? "?" + query : ""));

        /*
         * Performs the request.
         */
        response.parse(spServletTester.getResponses(request.generate()));

        System.out.println();
        System.out.println("Response status: " + response.getStatus());
        String location = response.getHeader("Location");
        System.out.println("Response Location header: " + location);
        if (location != null) {
            System.out.println("Response Location header length: " + location.length());
        }
        System.out.println();

        assertEquals(HttpServletResponse.SC_FOUND, response.getStatus());
        assertNotNull(location);
        Reference redirectRef = new Reference(location);
        assertNotNull(redirectRef.getQueryAsForm().getFirstValue("SAMLRequest"));
        assertTrue(redirectRef.getQueryAsForm().getFirstValue("SAMLRequest").length() > 0);
        return redirectRef;
    }

    /**
     * Tests the initial redirection.
     */
    @Test
    public void testInitialRedirect() throws Throwable {
        doInitialRedirect();
    }

    /**
     * Performs the redirection to the Idp
     * 
     * @param resourceRef
     *            IdP URI (including SAMLRequest in query)
     * @return Reference to the Location in the response header.
     * @throws Throwable
     */
    public Reference doRedirectToIdP(Reference resourceRef) throws Throwable {
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setHeader("Host", resourceRef.getHostDomain());
        request.setMethod("GET");
        String query = resourceRef.getQuery();
        request.setURI(resourceRef.getPath() + (query != null ? "?" + query : ""));

        /*
         * Performs the request.
         */
        response.parse(idpServletTester.getResponses(request.generate()));

        System.out.println();
        System.out.println("Response status: " + response.getStatus());
        String location = response.getHeader("Location");
        System.out.println("Response Location header: " + location);
        if (location != null) {
            System.out.println("Response Location header length: " + location.length());
        }
        System.out.println();

        return new Reference(location);
    }

    /**
     * Makes the initial request and then redirects to the IdP.
     * 
     * @throws Throwable
     */
    @Test
    public void testRedirectToIdp() throws Throwable {
        Reference redirectRef = doInitialRedirect();
        doRedirectToIdP(redirectRef);
    }

    /**
     * Initial request to SP, then IdP, then back to SP.
     * 
     * @throws Throwable
     */
    @Test
    public void testRedirectToSp() throws Throwable {
        Reference resourceRef = doRedirectToIdP(doInitialRedirect());

        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setHeader("Host", resourceRef.getHostDomain());
        request.setMethod("GET");
        String query = resourceRef.getQuery();
        request.setURI(resourceRef.getPath() + (query != null ? "?" + query : ""));

        /*
         * Performs the request.
         */
        response.parse(spServletTester.getResponses(request.generate()));

        System.out.println();
        System.out.println("Response status: " + response.getStatus());
        assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        String location = response.getHeader("Location");
        System.out.println("Response Location header: " + location);
        if (location != null) {
            System.out.println("Response Location header length: " + location.length());
        }
        System.out.println("Response content: " + response.getContent());
        System.out.println();
        assertEquals(TEST_BRUNO_FOAF_ID, response.getContent());
    }

    /**
     * 
     * This filter is used for the test: it fakes the presence of a client
     * certificate in the request.
     * 
     * @author Bruno Harbulot.
     * 
     */
    public static class FakeClientCertInsertionFilter implements Filter {
        static {
            Security.addProvider(new BouncyCastleProvider());
        }

        private X509Certificate x509Certificate;

        @Override
        public void destroy() {
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain next)
                throws IOException, ServletException {
            request.setAttribute("javax.servlet.request.X509Certificate",
                    new X509Certificate[] { x509Certificate });
            next.doFilter(request, response);
        }

        @Override
        public void init(FilterConfig config) throws ServletException {
            try {
                InputStreamReader certReader = new InputStreamReader(SpServletTest.class
                        .getResourceAsStream(TEST_BRUNO_CERT_FILENAME));

                PEMReader pemReader = new PEMReader(certReader);
                while (pemReader.ready()) {
                    Object pemObject = pemReader.readObject();
                    if (pemObject instanceof X509Certificate) {
                        x509Certificate = (X509Certificate) pemObject;
                        break;
                    } else {
                        throw new RuntimeException("Unknown type of PEM object: " + pemObject);
                    }
                }
                pemReader.close();
            } catch (IOException e) {
                throw new ServletException(e);
            }
        }
    }
}
