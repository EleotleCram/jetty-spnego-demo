package com.example;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.sourceforge.spnego.DelegateServletRequest;
import net.sourceforge.spnego.SpnegoHttpURLConnection;
import net.sourceforge.spnego.SpnegoLogonInfo;
import net.sourceforge.spnego.SpnegoPrincipal;
import org.apache.commons.io.IOUtils;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

/**
 * Delegating Hello Servlet that is intended to be used in combination with the SpnegoHttpFilter
 * (and the Hello Spnego Servlet).
 * It shows how single sign on (SSO) can be achieved using SPNEGO, and, if available,
 * how to delegate credentials to another servlet using spnego.
 *
 * Note: On http://spnego.sourceforge.net this file is known as "hello_delegate.jsp", it has
 * been adapted to run as a standalone servlet (i.e. on Jetty or some other web container).
 */
public class DelegatingHelloSpnegoServlet extends HttpServlet {

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_OK);
		PrintWriter out = response.getWriter();

		out.println("<h1>Delegating SPNEGO via ServletFilter Hello Servlet</h1>");

		if (request instanceof DelegateServletRequest) {
			DelegateServletRequest dsr = (DelegateServletRequest) request;
			GSSCredential creds = dsr.getDelegatedCredential();

			if (null == creds) {
				out.print("No delegated creds.");
			} else {
				try {
					out.print(creds.getName().toString());

					SpnegoHttpURLConnection spnego =
							new SpnegoHttpURLConnection(creds);

					spnego.connect(new URL("http://example.com:8080/filtered/spnego"));

					out.print("<br />HTTP Status Code: " + spnego.getResponseCode());
					out.print("<br />HTTP Status Message: " + spnego.getResponseMessage());
					out.print("<br /><br />");

					out.println("<div style=\"margin: 1em; border: 1px solid #444; background-color: #DDD; overflow: auto; color: #555;\">");
					out.print(IOUtils.toString(spnego.getInputStream()));
					out.println("</div>");

					spnego.disconnect();
				} catch (PrivilegedActionException ex) {
					throw new ServletException(ex);
				} catch (GSSException ex) {
					throw new ServletException(ex);
				}
			}

		} else {
			out.print("Request not a delegate.");
		}
	}
}
