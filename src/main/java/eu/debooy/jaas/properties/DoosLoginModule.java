/**
 * Copyright 2015 Marco de Booij
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * you may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 *
 * http://www.osor.eu/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.debooy.jaas.properties;

import eu.debooy.jaas.RolePrincipal;
import eu.debooy.jaas.UserPrincipal;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.openejb.loader.IO;
import org.apache.openejb.util.ConfUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Marco de Booij
 */
public class DoosLoginModule implements LoginModule {
  private static final String GROUP_FILE      = "GroupsFile";
  private static final String LOGIN_EXCEPTION = "error.authenticatie.verkeerd";
  private static final String USER_FILE       = "UsersFile";
  private static final String USERINFO_FILE   = "UsersinfoFile";

  private static Logger logger  =
      LoggerFactory.getLogger(DoosLoginModule.class);

  private boolean             debug;
  private Properties          groups;
  private URL                 groupsUrl;
  private CallbackHandler     handler;
  private List<RolePrincipal> rolePrincipals;
  private Subject             subject;
  private String              user;
  private boolean             userinfo;
  private UserPrincipal       userPrincipal;
  private Properties          users;
  private Properties          usersinfo;
  private URL                 usersinfoUrl;
  private URL                 usersUrl;

  public DoosLoginModule() {
    groups    = new Properties();
    userinfo  = true;
    users     = new Properties();
    usersinfo = new Properties();
  }

  /**
   * Stop het aanmelden.
   * 
   * @exception LoginException als de abort faalt.
   */
  public boolean abort() throws LoginException {
    if (null == userPrincipal) {
      return false;
    }

    clear();

    return true;
  }

  /**
   * Ruim de gebruikers rechten op.
   */
  private void clear() {
    this.rolePrincipals.clear();
    this.userPrincipal  = null;
  }

  /**
   * Zet de UserPrincipal en RolePrincipal.
   * 
   * @exception LoginException als de commit faalt.
   */
  public boolean commit() throws LoginException {
    if (null == userPrincipal) {
      return false;
    }

    subject.getPrincipals().add(userPrincipal);
    subject.getPrincipals().addAll(rolePrincipals);
    clear();

    return true;
  }

  /**
   * Initialiseer de DoosLoginModule.
   */
  public void initialize(Subject subject, CallbackHandler handler,
                         Map<String, ?> sharedState, Map<String, ?> options) {
    this.subject = subject;
    this.handler = handler;

    debug = ((logger.isDebugEnabled())
        || ("true".equalsIgnoreCase(String.valueOf(options.get("debug")))));

    String  groupsFile    = String.valueOf(options.get(GROUP_FILE));
    String  usersFile     = String.valueOf(options.get(USER_FILE));
    String  usersinfoFile = String.valueOf(options.get(USERINFO_FILE));
    if (null == usersinfoFile) {
      usersinfoFile = "";
    }

    groupsUrl     = ConfUtils.getConfResource(groupsFile);
    usersUrl      = ConfUtils.getConfResource(usersFile);
    if (!usersinfoFile.equals("")) {
      userinfo  = false;
    }

    if (debug) {
      logger.debug("Users file: " + usersUrl.toExternalForm());
      logger.debug("Usersinfo file: " + usersinfoUrl.toExternalForm());
      logger.debug("Groups file: " + groupsUrl.toExternalForm());
    }
  }

  /**
   * Controleer de credentials.
   * 
   * @exception LoginException als het authenticatie faalt.
   */
  public boolean login() throws LoginException {
    try {
      users = IO.readProperties(usersUrl);
    } catch (IOException e) {
      throw new LoginException("Unable to load user properties file "
                               + usersUrl.getFile());
    }

    Callback[] callbacks = new Callback[2];
    callbacks[0]  = new NameCallback("login");
    callbacks[1]  = new PasswordCallback("password", false);

    try {
      handler.handle(callbacks);
    } catch (IOException e) {
      throw new LoginException(e.getMessage());
    } catch (UnsupportedCallbackException e) {
      throw new LoginException(e.getMessage() + " " + LOGIN_EXCEPTION);
    }

    user  = ((NameCallback) callbacks[0]).getName();
    char[]  checkPassword = ((PasswordCallback) callbacks[1]).getPassword();
    if (checkPassword == null) {
      checkPassword = new char[0];
    }

    String  password  = users.getProperty(user);
    if (password == null) {
      throw new FailedLoginException(LOGIN_EXCEPTION);
    }

    if (!password.equals(new String(checkPassword))) {
      throw new FailedLoginException(LOGIN_EXCEPTION);
    }

    users.clear();
    userPrincipal = new UserPrincipal(user);

    // Haal extra gebruikers informatie.
    if (userinfo) {
      try {
        usersinfo = IO.readProperties(usersinfoUrl);
        String[]  userinfo  = usersinfo.getProperty(user).split(",");
        userPrincipal.setEmail(userinfo[0]);
        userPrincipal.setVolledigeNaam(userinfo[1]);
      } catch (IOException e) {
        throw new LoginException("Unable to load userinfo properties file "
                                 + groupsUrl.getFile());
      }
      usersinfo.clear();
    }

    // Haal de rollen/groepen van de user op.
    try {
      groups  = IO.readProperties(groupsUrl);
      Enumeration<Object> keys  = groups.keys();
      while (keys.hasMoreElements()) {
        String    group     = (String) keys.nextElement();
        String[]  userlist  = groups.getProperty(group).split(",");
        for (int i = 0; i < userlist.length; i++) {
          if (userlist[i].equals(user)) {
            rolePrincipals.add(new RolePrincipal(group));
            break;
          }
        }
      }
      if (debug) {
        StringBuilder      rollen  = new StringBuilder();
        for (RolePrincipal rol : rolePrincipals) {
          rollen.append(", ").append(rol);
        }
        logger.debug(rollen.toString().substring(2));
      }
    } catch (IOException e) {
      throw new LoginException("Unable to load group properties file "
                               + groupsUrl.getFile());
    }
    groups.clear();

    if (debug) {
      logger.debug("Logged in as '" + user + "'");
    }

    return true;
  }

  /**
   * Doe een logout.
   * 
   * @exception LoginException als de logout faalt.
   */
  public boolean logout() throws LoginException {
    subject.getPrincipals().remove(userPrincipal);
    subject.getPrincipals().removeAll(rolePrincipals);
    clear();

    return true;
  }
}
