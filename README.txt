Copyright (c) 2009, The University of Manchester, United Kingdom.
All rights reserved.

This project is produced by Bruno Harbulot (The University of Manchester, UK)
and is released under the new BSD licence. (See LICENSE.txt.)



This is a Identity Provider (IdP) and a Service Provider (SP) implementation
to allow an non-SSL website (the SP) to use a FOAF+SSL trusted authenticator
site (the IdP).

This uses the SAML HTTP Redirect Binding [1] (Section 3.4).

The implementation is based on OpenSAML [2] (which uses Apache XML security,
Santuario [3]) and on the FOAF+SSL verifier in the Sommer project [4].
The tests also use BouncyCastle, Jetty, Restlet and jSSLutils.


[1] <http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>
[2] <http://www.opensaml.org/>
[3] <http://santuario.apache.org/>
[4] <http://sommer.dev.java.net/>


__ Status __

This is work in progress, but this should provide the minimum required for 
Servlet integration.
The Restlet integration is a very early draft.

Both the SP servlet and the IdP servlet come with jUnit tests which 
demonstrate how they work.


__ Sample SAML assertion __

___ Signed response ___

<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://sp.example.com/sp/" Version="2.0"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://idp.example.org/idp/</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="ds saml"/></ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>ttiIKi8K9Ls5i2djIJO65EOzUBI=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
nsjRKNMRxDXrtcsFrgNDX4Zh0ZwsRyubaGrXQbfphoH+iVbjimpUrb5VXwwUi1Y5cKp4t4khVT05
yEoqz9teovrPdMz3N5UYfYixENv52p896A2sHlSDkpg6pZq7MOOxlDhhQEN/efieRaWnvDYd6ow6
Tm35u2tCH6eC4B/QapI=
</ds:SignatureValue>
<ds:KeyInfo><ds:KeyName>http://idp.example.org/idp/#pubkey</ds:KeyName></ds:KeyInfo></ds:Signature><saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:NameID>http://foaf.example.net/bruno#me</saml:NameID></saml:Subject><saml:Conditions xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/sp/</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2009-03-24T22:34:20.579Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></saml:Assertion></samlp:Response>


Because we assume the SP trusts only one IdP (and the SP knows the IdP's 
public key), we can omit the key value in <ds:KeyInfo/>. We just use a name
as an indication.


___ Signed assertion, without the signature ___

<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
  <saml:Issuer>http://idp.example.org/idp/</saml:Issuer>
  <saml:Subject>
    <saml:NameID>http://foaf.example.net/bruno#me</saml:NameID>
  </saml:Subject>
  <saml:Conditions>
    <saml:AudienceRestriction>
      <saml:Audience>http://sp.example.com/sp/</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="2009-03-24T22:34:20.579Z"/>
</saml:Assertion>


This gives:
  - the ID of the subject:
        <saml:NameID>http://foaf.example.net/bruno#me</saml:NameID>
  - an authentication with a time: 
        <saml:AuthnStatement AuthnInstant="2009-03-24T22:34:20.579Z"/>
  - the intended audience for this assertion:
        <saml:Audience>http://sp.example.com/sp/</saml:Audience>


___ URL query encoding ___

The SAML assertion above is encoded in the query in this form:

http://sp.example.com/sp/?SAMLResponse=nVVdc6owEH3vr2Dw0dGAOtUyakettl61Xr%2
BrbwgLRCFBEvz69RcQ1Dptp9c3Ttg952x2k5Sf944tbMFjmJKKKGclUQCiUR0TsyJOxq1MSXyul
pnq2K4yBOZSwkAIcghTosWK6HtEoSrDTCGqA0zhmjKq9bpKLisprkc51agtCi%2FAOCYqj2Qszl
0FIeZmYa86rg1ZjToBRKIwTawE6eJJWKkxBl6YeSX8s66aZHxN2GbMB%2B8OtmrsHOsX69QzQ4z
K6Iq7WtaZMsJmULHvJRums3Ppu90uu8tHuTlJkpD0hIIYnWEzJVYfkmTQ28SgJ9xQCSVYU218jH
axB9yiulCzTephbjnfUMtIlkLqDOy1jCYXSEpEF4HI3S%2BZPpn0mJphlionZEMwwAsGB4TJsF0
R4xrGnkqYQT2H3eD%2FEwOyBZu6oGdY4jnR%2FT3jFxtRLYOmtIlm%2Bwxv4T3su6tqwOJ2gfZ7
KuGvBwbedzHjFVFnQjgKgccyuvYYWEZf7MoLNoPDcU8XrjtwYpmqtg%2FVnL%2BepBedBd036Oq
Psd%2Fw90G6JffdhVmJLFwHn0ydGxjj2%2FE7T0ucBA3UYz0q9%2BdzsiweCpvWZHWU0ofSUZo8
pruIbda8Dmbf4MXVfJ%2Fu6HmnVp806yQ9p48z3IZZv7iytMOe4PnDoH%2FsNZuvfD2SUTPnrTb
dFeeb1oc5G3WOb9bbcFfczM2Ws5Hr3W2zNl4ZVrvbHNRaaTI4OppmOaUPKk2nhy16feBzS5%2B9
48OyOMnX60XyWBtULjVd1xDW1YFDVGT8HQ7BT4c85frLNRwiuiQ8ASeeT0LxfTPylyvQ%2BD0Xz
okg1Gm%2FJMYMqhpnZwQ4Wno%2BoSkH4isojo5RLB4zNSjRcUjN7ndT83UcjkrwHnAPa%2BGvmz
%2FVb2%2F42NQ58AZ%2FokQ3js8i3CIjrnJwgHAhgm3CuEqCsxcckaeMlM%2FkCuNcTskXlHwx%
2ByiXFuId5aKzu2QpXrg8hdV%2F

This makes a query parameter which is about 1000-character long.




__ How to build __

You need Maven 2.

___ Maven 2 repositories ___

You need to add these repositories to your $HOME/.m2/settings.xml (or Windows 
equivalent):
  - http://shibboleth.internet2.edu/downloads/maven2
  - http://repo.aduna-software.org/maven2/releases
  - http://maven.restlet.org


___ FOAF+SSL Verifier dependency ___

The current version uses the FOAF+SSL verifier in the Sommer repository.
(Revision 467)

  svn co https://sommer.dev.java.net/svn/sommer/maven/foafssl
  cd foafssl
  mvn clean install
  
___ Building ___

  In the 'samlredirector' repository, use 'mvn clean install'


___ Sample Maven 2 settings.xml ___

<?xml version="1.0"?>
<settings>
        <profiles>
                <profile>
                        <id>FOAFSSL</id>
                        <repositories>
                                <repository>
                                        <id>maven-restlet</id>
                                        <name>Public online Restlet repository</name>
                                        <url>http://maven.restlet.org</url>
                                        <snapshots>
                                                <enabled>false</enabled>
                                        </snapshots>
                                        <releases>
                                                <enabled>true</enabled>
                                        </releases>
                                </repository>
                                <repository>
                                        <id>shibboleth-opensaml</id>
                                        <name>Shibboleth - OpenSAML</name>
                                        <url>http://shibboleth.internet2.edu/downloads/maven2</url>
                                        <layout>default</layout>
                                        <snapshots>
                                                <enabled>false</enabled>
                                        </snapshots>
                                        <releases>
                                                <enabled>true</enabled>
                                        </releases>
                                </repository>
                                <repository>
                                        <id>aduna</id>
                                        <name>Aduna</name>
                                        <url>
                                                http://repo.aduna-software.org/maven2/releases
                                        </url>
                                        <layout>default</layout>
                                        <snapshots>
                                                <enabled>false</enabled>
                                        </snapshots>
                                        <releases>
                                                <enabled>true</enabled>
                                        </releases>
                                </repository>
                        </repositories>
                </profile>
        </profiles>
        <activeProfiles>
                <activeProfile>FOAFSSL</activeProfile>
        </activeProfiles>
</settings>
