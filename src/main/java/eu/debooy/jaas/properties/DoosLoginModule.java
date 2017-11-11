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
import eu.debooy.jaas.SpiLoginModule;
import eu.debooy.jaas.UserPrincipal;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
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

import org.apache.openejb.loader.IO;
import org.apache.openejb.util.ConfUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author Marco de Booij
 * 
 * Deze class zorgt ervoor dat de UserPrincipal ook wordt gevuld met het e-mail
 * adres en de volledige naam van de gebruiker.
 * 
 * @see javax.security.auth.spi.LoginModule
 */
public class DoosLoginModule extends SpiLoginModule {
  private static final String GROUP_FILE      = "GroupsFile";
  private static final String LOGIN_EXCEPTION = "error.authenticatie.verkeerd";
  private static final String USER_FILE       = "UsersFile";

  private static Logger logger  =
      LoggerFactory.getLogger(DoosLoginModule.class);

  private URL groups;
  private URL users;

  /**
   * Initialiseer de DoosLoginModule.
   */
  public void initialize(Subject subject, CallbackHandler handler,
                         Map<String, ?> sharedState, Map<String, ?> options) {
    this.subject = subject;
    this.handler = handler;

    debug = "true".equalsIgnoreCase(String.valueOf(options.get("debug")));

    if (!options.containsKey(USER_FILE) || !options.containsKey(GROUP_FILE)) {
      logger.error("Missing " + USER_FILE + " and/or " + GROUP_FILE);
      return;
    }

    users   =
        ConfUtils.getConfResource(String.valueOf(options.get(USER_FILE)));
    groups  =
        ConfUtils.getConfResource(String.valueOf(options.get(GROUP_FILE)));

    logger.debug("Users file: " + users.toExternalForm());
    logger.debug("Groups file: " + groups.toExternalForm());
  }

  /**
   * Controleer de credentials.
   * 
   * @exception LoginException als het authenticatie faalt.
   */
  public boolean login() throws LoginException {
    Properties  props;
    try {
      props = IO.readProperties(users);
    } catch (IOException e) {
      logger.error(LOGIN_EXCEPTION, e);
      throw new LoginException("Unable to load user properties file "
                               + users.getFile());
    }

    Callback[] callbacks = new Callback[2];
    callbacks[0]  = new NameCallback("login");
    callbacks[1]  = new PasswordCallback("password", false);

    try {
      handler.handle(callbacks);
    } catch (IOException e) {
      logger.error(LOGIN_EXCEPTION, e);
      throw new LoginException(e.getMessage());
    } catch (UnsupportedCallbackException e) {
      logger.error(LOGIN_EXCEPTION, e);
      throw new LoginException(e.getMessage() + " " + LOGIN_EXCEPTION);
    }

    String  user      = ((NameCallback) callbacks[0]).getName();
    String  password  =
        String.valueOf(((PasswordCallback) callbacks[1]).getPassword());

    // Informatie van de gebruiker. Er zijn 3 mogelijke 'velden':
    // 0 password
    // 1 Volledige naam
    // 2 e-mail adres
    String[]  info      = props.getProperty(user).split("\t", -1);
    if (info[0] == null) {
      throw new FailedLoginException(LOGIN_EXCEPTION);
    }

    if (!info[0].equals(password)) {
      throw new FailedLoginException(LOGIN_EXCEPTION);
    }

    userPrincipal = new UserPrincipal(user);
    // Vul extra gebruikers informatie indien aanwezig.
    if (info.length > 1) {
      userPrincipal.setVolledigeNaam(info[1]);
      if (info.length > 2) {
        userPrincipal.setEmail(info[2]);
      }
    }

    // Haal de rollen/groepen van de user op.
    try {
      props           = IO.readProperties(groups);
      rolePrincipals  = new ArrayList<RolePrincipal>();
      Enumeration<Object> keys  = props.keys();
      while (keys.hasMoreElements()) {
        String    group     = (String) keys.nextElement();
        String[]  userlist  = props.getProperty(group).split(",");
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
        logger.debug("Groups: " + rollen.toString().substring(2));
      }
    } catch (IOException e) {
      logger.error(LOGIN_EXCEPTION, e);
      throw new LoginException("Unable to load group properties file "
                               + groups.getFile());
    }

    if (debug) {
      logger.debug("Logged in as: " + userPrincipal.toString());
    }

    return true;
  }
}
