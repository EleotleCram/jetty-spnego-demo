/**
 *	A short prefatory note.
 *
 *	Large parts of this file are based on[1, 2], and I also use
 *  important parts of [3, 4]. Kudos to those guys, they made this
 *  possible, I just combined the ingredients.
 *
 *	I basically removed the wicket stuff from [1] (distracted from
 *  the goal; explain the underlying mechanisms of Spnego) and turned
 *  it into a bare-bones HttpServlet.
 *
 *  Then I changed the serverside credential part a bit so that
 *  it doesn't need a keytab file --which just adds another step in
 *  an already complex mix of elements (i.e. how to make a correct
 *  keytab file (key version, encryption types, SPNs... a mismatch
 *  in any of these and the whole authentication would have failed
 *  miserably)). So, instead of a keytab file, for the sake of
 *  simplicity, this example servlet simply uses a hard-coded
 *  username/password combination.
 * 
 *  Furthermore, I also show how to use the jaaslounge-decoding
 *  package[3] to retrieve the Microsoft PAC authorization data
 *  from an Active Directory issued Kerberos ticket. For instance,
 *  to read the Group SIDs of the authenticated user.
 *
 *  __
 *  Marcel Toele, Spring 2012.
 *
 * [1] - https://cwiki.apache.org/DIRxINTEROP/kerberos-authentication-to-wicket.html
 * [2] - http://spnego.sourceforge.net/
 * [3] - http://jaaslounge.sourceforge.net/
 * [4] - http://www.bouncycastle.org/
 */

/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package com.example;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.sourceforge.spnego.Base64;
import net.sourceforge.spnego.SpnegoProvider;
import org.apache.commons.collections.IteratorUtils;
import org.ietf.jgss.*;
import org.jaaslounge.decoding.DecodingException;
import org.jaaslounge.decoding.kerberos.KerberosAuthData;
import org.jaaslounge.decoding.kerberos.KerberosPacAuthData;
import org.jaaslounge.decoding.kerberos.KerberosToken;
import org.jaaslounge.decoding.pac.PacSid;
import org.jaaslounge.decoding.spnego.SpnegoToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple example of an access protected hello page that processes SPNEGO GSS-API Kerberos authentication.
 *
 * This class basically is the same as the FilteredHelloSpnegoServlet, but exposes the underlying 
 * mechanisms that are otherwise handled by the spnego-filter servlet. (So, if you use the spnego-filter,
 * you *DO NOT NEED ALL THIS CODE* !!!)
 */
public class ManualSpnegoNegotiateServlet extends HttpServlet {

	private static final Logger log = LoggerFactory.getLogger(ManualSpnegoNegotiateServlet.class);
	/**
	 * Constant for the header lead for the unsupported NTLM mechanism.
	 */
	private static final byte NTLMSSP[] = {(byte) 0x4E, (byte) 0x54, (byte) 0x4C, (byte) 0x4D, (byte) 0x53, (byte) 0x53, (byte) 0x50};

	/**
	 * ManualSpnegoNegotiateServlet.
	 */
	public ManualSpnegoNegotiateServlet() {
		System.setProperty("java.security.auth.login.config", "src/main/conf/spnego.conf");
		System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
		System.setProperty("sun.security.spnego.msinterop", "true"); // true by default
		System.setProperty("sun.security.spnego.debug", "false"); // false by default
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		response.getWriter().println("<h1>Manual SPNEGO Negotiate Hello Servlet</h1>");
		response.getWriter().println("<pre>");
		try {
			if (attemptNegotiation(request, response)) {
				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().println("Authenticated.");
			} else {
				response.getWriter().println("Authentication failed, sorry.");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		response.getWriter().println("</pre>");
	}

	/**
	 * Use of Kerberos is wrapped in an HTTP auth-scheme of "Negotiate" [RFC 4559].
	 *
	 * The auth-params exchanged use data formats defined for use with the GSS-API [RFC 2743]. In particular, they follow the formats set for the SPNEGO [RFC 4178] and
	 * Kerberos [RFC 4121] mechanisms for GSSAPI. The "Negotiate" auth-scheme calls for the use of SPNEGO GSSAPI tokens that the specific mechanism type specifies.
	 *
	 * The current implementation of this protocol is limited to the use of SPNEGO with the Kerberos protocol.
	 *
	 * @param request
	 * @param response
	 * @throws ServletException
	 *
	 * @return true upon successful authentication, false otherwise
	 */
	protected boolean attemptNegotiation(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, UnsupportedEncodingException, IOException {
		log.debug("Attempting negotiation.");

		String header = request.getHeader("Authorization");

		/**
		 * Guard clause to check for Negotiate header.
		 *
		 * If the server receives a request for an access-protected object, and if an acceptable Authorization header has not been sent, the server responds with a "401
		 * Unauthorized" status code, and a "WWW-Authenticate:" header as per the framework described in [RFC 2616]. The initial WWW-Authenticate header will not carry
		 * any gssapi-data.
		 */
		if (header == null || header.length() < 10 || !header.startsWith("Negotiate ")) {
			response.setHeader("WWW-Authenticate", "Negotiate");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			log.debug("Proper authorization header not found, returning challenge.");
			return false;
		}

		/**
		 * A client may initiate a connection to the server with an "Authorization" header containing the initial token for the server. This form will bypass the initial
		 * 401 error from the server when the client knows that the server will accept the Negotiate HTTP authentication type.
		 */
		log.debug("Authorization header found, continuing negotiation.");

		/**
		 * The data following the word Negotiate is the GSS-API data to process.
		 */
		byte gssapiData[] = Base64.decode(header.substring(10));

		log.debug("GSS API data: " + Arrays.toString(gssapiData));

		/**
		 * Guard clause to check for the unsupported NTLM authentication mechanism.
		 */
		if (isNtlmMechanism(gssapiData)) {
			log.warn("Got request for unsupported NTLM mechanism, aborting negotiation.");
			return false;
		}

		/**
		 * The server attempts to establish a security context. Establishment may result in tokens that the server must return to the client. Tokens are BASE-64 encoded
		 * GSS-API data.
		 */
		GSSContext gssContext = null;
		LoginContext loginContext = null;
		String outToken = null;

		try {
			final String domainUsername = "Zeus";
			final String domainUserPassword = "Z3usP@55";
			final CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(domainUsername, domainUserPassword);

			loginContext = new LoginContext("spnego-server", handler);
			loginContext.login();
			Subject subject = loginContext.getSubject();

			Oid spnegoOid = new Oid("1.3.6.1.5.5.2"); // for spnego answers
			Oid kerbv5Oid = new Oid("1.2.840.113554.1.2.2"); // for chromium (they send a kerbv5 token instead of spnego)
			final Oid[] oids = new Oid[]{spnegoOid, kerbv5Oid};

			final GSSManager manager = GSSManager.getInstance();
			final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
                public GSSCredential run() throws GSSException {
                    return manager.createCredential(
                        null,
                        GSSCredential.INDEFINITE_LIFETIME,
                        oids,
                        GSSCredential.ACCEPT_ONLY
					);
                }
            };

			GSSCredential serverCreds = Subject.doAs(subject, action);

			log.debug("Mechs: " + Arrays.toString(serverCreds.getMechs()));

			gssContext = manager.createContext(serverCreds);

			log.debug("Context created. " + gssContext);

			byte tokenBytes[] = gssContext.acceptSecContext(gssapiData, 0, gssapiData.length);
			outToken = Base64.encode(tokenBytes);
		} catch (PrivilegedActionException ex) {
			log.error("", ex);
		} catch (LoginException ex) {
			log.error("", ex);
		} catch (GSSException gsse) {
			gsse.printStackTrace();
			log.error("GSSException:       " + gsse.getMessage());
			log.error("GSSException major: " + gsse.getMajorString());
			log.error("GSSException minor: " + gsse.getMinorString());
			throw new ServletException(gsse);
		}

		/**
		 * If the context is established, we can attempt to retrieve the name of the "context initiator." In the case of the Kerberos mechanism, the context initiator is
		 * the Kerberos principal of the client. Additionally, the client may be delegating credentials.
		 */
		if (gssContext != null && gssContext.isEstablished()) {
			log.debug("Context established, attempting Kerberos principal retrieval.");

			try {
				Subject subject = new Subject();
				GSSName clientGSSName = gssContext.getSrcName();
				KerberosPrincipal clientPrincipal = new KerberosPrincipal(clientGSSName.toString());
				subject.getPrincipals().add(clientPrincipal);
				log.info("Got client Kerberos principal: " + clientGSSName);
				response.getWriter().println("Hello, " + clientPrincipal);


				/**
				 * Retrieve LogonInfo (for example, GroupSIDs) from the PAC Authorization Data
				 * from a Kerberos Ticket that was issued by Active Directory.
				 */
				byte[] kerberosTokenData = gssapiData;
				try {
					SpnegoToken token = SpnegoToken.parse(gssapiData);
					kerberosTokenData = token.getMechanismToken();
				} catch (DecodingException dex) {
					// Chromium bug: sends a Kerberos response instead of an spnego response with a Kerberos mechanism
				} catch (Exception ex) {
					log.error("", ex);
				}

				try {
					Object[] keyObjs = IteratorUtils.toArray(loginContext.getSubject().getPrivateCredentials(KerberosKey.class).iterator());
					KerberosKey[] keys = new KerberosKey[keyObjs.length];
					System.arraycopy(keyObjs, 0, keys, 0, keyObjs.length);

					KerberosToken token = new KerberosToken(kerberosTokenData, keys);
					log.info("Authorizations: ");
					for (KerberosAuthData authData : token.getTicket().getEncData().getUserAuthorizations()) {
						if (authData instanceof KerberosPacAuthData) {
							PacSid[] groupSIDs = ((KerberosPacAuthData) authData).getPac().getLogonInfo().getGroupSids();
							log.info("GroupSids: " + Arrays.toString(groupSIDs));
							response.getWriter().println("Found group SIDs: " + Arrays.toString(groupSIDs));
						} else {
							log.info("AuthData without PAC: " + authData.toString());
						}
					}
				} catch (Exception ex) {
					log.error("", ex);
				}

				if (gssContext.getCredDelegState()) {
					GSSCredential delegateCredential = gssContext.getDelegCred();
					GSSName delegateGSSName = delegateCredential.getName();
					Principal delegatePrincipal = new KerberosPrincipal(delegateGSSName.toString());
					subject.getPrincipals().add(delegatePrincipal);
					subject.getPrivateCredentials().add(delegateCredential);
					log.info("Got delegated Kerberos principal: " + delegateGSSName);
				}

				/**
				 * A status code 200 status response can also carry a "WWW-Authenticate" response header containing the final leg of an authentication. In this case, the
				 * gssapi-data will be present.
				 */
				if (outToken != null && outToken.length() > 0) {
					response.setHeader("WWW-Authenticate", "Negotiate " + outToken.getBytes());
					response.setStatus(HttpServletResponse.SC_OK);
					log.debug("Returning final authentication data to client to complete context.");
					log.debug("Negotiation completed.");
					return true;
				}
			} catch (GSSException gsse) {
				log.error("GSSException:       " + gsse.getMessage());
				log.error("GSSException major: " + gsse.getMajorString());
				log.error("GSSException minor: " + gsse.getMinorString());

				response.addHeader("Client-Warning", gsse.getMessage());
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			}
		} else {
			/**
			 * Any returned code other than a success 2xx code represents an authentication error. If a 401 containing a "WWW-Authenticate" header with "Negotiate" and
			 * gssapi-data is returned from the server, it is a continuation of the authentication request.
			 */
			if (outToken != null && outToken.length() > 0) {
				response.setHeader("WWW-Authenticate", "Negotiate " + outToken.getBytes());
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				log.debug("Additional authentication processing required, returning token.");
				return false;
			} else {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				log.warn("Kerberos negotiation failed.");
			}
		}

		log.debug("Negotiation completed.");

		return true;
	}

	/**
	 * Check whether the Authorization header is attempting the unsupported NTLM mechanism.
	 *
	 * @param gssapiData Byte array retrieved from the Authorization header.
	 * @return true If the header contains an NTLM mechanism request.
	 */
	protected boolean isNtlmMechanism(byte[] gssapiData) {
		byte leadingBytes[] = new byte[7];
		System.arraycopy(gssapiData, 0, leadingBytes, 0, 7);
		if (Arrays.equals(leadingBytes, NTLMSSP)) {
			return true;
		}

		return false;
	}
}
