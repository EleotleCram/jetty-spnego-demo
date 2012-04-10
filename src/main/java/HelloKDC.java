/*
 * Copyright (C) 2009  "Darwin V. Felix" <dfelix@users.sourceforge.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

import java.io.File;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

public final class HelloKDC {

    private HelloKDC() {
        // default private
    }

    public static void main(final String[] args) throws Exception {

    	// Domain (pre-authentication) account
//        final String username = "HTTP/example.com"; // For Non-WIA authentication against libre Kerberos/LDAP servers
        final String username = "Zeus";

        // Password for the pre-auth acct.
        final String password = "Z3usP@55";

        // Name of our krb5 config file
        final String krbfile = "/etc/krb5.conf";

        // Name of our login config file
        final String loginfile = "src/main/conf/spnego.conf";

        // Name of our login module
        final String module = "spnego-client";

        // set some system properties
		System.setProperty("java.security.krb5.conf", krbfile);
		System.setProperty("java.security.auth.login.config", loginfile);
		System.setProperty("sun.security.krb5.debug", "true");

        // assert
        HelloKDC.validate(username, password, krbfile, loginfile, module);

        final CallbackHandler handler =
            HelloKDC.getUsernamePasswordHandler(username, password);

        final LoginContext loginContext = new LoginContext(module, handler);

        // attempt to login
        loginContext.login();

        // output some info
        System.out.println("Subject=" + loginContext.getSubject());

        // logout
        loginContext.logout();

        System.out.println("Connection test successful.");
    }

    private static void validate(final String username, final String password
        , final String krbfile, final String loginfile, final String moduleName)
        throws FileNotFoundException, NoSuchAlgorithmException {

        // confirm username was provided
        if (null == username || username.isEmpty()) {
            throw new IllegalArgumentException("Must provide a username");
        }

        // confirm password was provided
        if (null == password || password.isEmpty()) {
            throw new IllegalArgumentException("Must provide a password");
        }

        // confirm krb5.conf file exists
        if (null == krbfile || krbfile.isEmpty()) {
            throw new IllegalArgumentException("Must provide a krb5 file");
        } else {
            final File file = new File(krbfile);
            if (!file.exists()) {
                throw new FileNotFoundException(krbfile);
            }
        }

        // confirm loginfile
        if (null == loginfile || loginfile.isEmpty()) {
            throw new IllegalArgumentException("Must provide a login file");
        } else {
            final File file = new File(loginfile);
            if (!file.exists()) {
                throw new FileNotFoundException(loginfile);
            }
        }

        // confirm that runtime loaded the login file
        final Configuration config = Configuration.getConfiguration();

        // confirm that the module name exists in the file
        if (null == config.getAppConfigurationEntry(moduleName)) {
            throw new IllegalArgumentException("The module name "
                    + moduleName + " was not found in the login file");
        }
    }

    private static CallbackHandler getUsernamePasswordHandler(
        final String username, final String password) {

        final CallbackHandler handler = new CallbackHandler() {
            public void handle(final Callback[] callback) {
                for (int i=0; i<callback.length; i++) {
                    if (callback[i] instanceof NameCallback) {
                        final NameCallback nameCallback = (NameCallback) callback[i];
                        nameCallback.setName(username);
                    } else if (callback[i] instanceof PasswordCallback) {
                        final PasswordCallback passCallback = (PasswordCallback) callback[i];
                        passCallback.setPassword(password.toCharArray());
                    } else {
                        System.err.println("Unsupported Callback: "
                                + callback[i].getClass().getName());
                    }
                }
            }
        };

        return handler;
    }
}
