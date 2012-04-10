package com.example;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.sourceforge.spnego.SpnegoLogonInfo;
import net.sourceforge.spnego.SpnegoPrincipal;

/**
 * Hello Servlet that is intended to be used in combination with the SpnegoHttpFilter.
 * It shows how single sign on (SSO) can be achieved using SPNEGO, and, if available,
 * how to read the group SIDs (Active Directory/Samba4 issued Kerberos tickets).
 *
 * All complexities are encapsulated by the filter, so this file shows simply how
 * to get to the data. If you want to learn about the details involved to achieve
 * all this beauty, please check out: ManualSpnegoNegotiateServlet, which basically
 * does the same thing, but with all implementation details exposed.
 *
 * @author mtoele
 */
public class HelloSpnegoServlet extends HttpServlet
{
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        response.setContentType("text/html");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().println("<h1>SPNEGO via ServletFilter Hello Servlet</h1>");
		response.getWriter().println("<pre>");

		Principal principal = request.getUserPrincipal();
        response.getWriter().println("Hello, " + principal);

		if(principal instanceof SpnegoPrincipal) {
			SpnegoPrincipal spnegoPrincipal = (SpnegoPrincipal)principal;
			SpnegoLogonInfo logonInfo = spnegoPrincipal.getLogonInfo();
			if(logonInfo != null) {
				String[] groupSIDs = logonInfo.getGroupSids();
				response.getWriter().println("Found group SIDs: " + Arrays.toString(groupSIDs));
			} else {
				response.getWriter().println("No logon info available for principal.");
			}
		}

		response.getWriter().println("Authenticated.");

		response.getWriter().println("</pre>");
    }
}

