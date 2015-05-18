/**
 * Copyright 2014 Marco de Booij
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
package eu.debooy.jaas.ldap;

import eu.debooy.jaas.RolePrincipal;
import eu.debooy.jaas.UserPrincipal;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

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
public class DoosLoginModule implements LoginModule {
  private static final  String  LOGIN_EXCEPTION =
      "error.authenticatie.verkeerd";

  private static Logger logger  =
      LoggerFactory.getLogger(DoosLoginModule.class);

  private boolean             debug;
  private CallbackHandler     handler;
  private Properties          ldap;
  private List<RolePrincipal> rolePrincipals;
  private Subject             subject;
  private UserPrincipal       userPrincipal;

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
    this.handler      = handler;
    debug             = logger.isDebugEnabled()
        || "true".equalsIgnoreCase(String.valueOf(options.get("debug")));
    this.subject      = subject;
    ldap              = new Properties();
    String[] waardes  = new String[]{"checkPassword", "factoriesControl",
                                     "factoriesInitctx", "host", "password",
                                     "roleSearch", "roleSearchbase", "user",
                                     "userSearch", "userSearchbase"};
    for (String waarde : waardes) {
      if (options.containsKey(waarde)) {
        ldap.put(waarde, String.valueOf(options.get(waarde)));
      }
    }
  }

  /**
   * Controleer de credentials.
   * 
   * @exception LoginException als het authenticatie faalt.
   */
  public boolean login() throws LoginException {
    Callback[]  callbacks = new Callback[2];
    callbacks[0]  = new NameCallback("login");
    callbacks[1]  = new PasswordCallback("password", false);

    try {
      handler.handle(callbacks);
      String          login     = ((NameCallback) callbacks[0]).getName();
      String          password  =
          String.valueOf(((PasswordCallback) callbacks[1]).getPassword());

      // Aanmelden aan de LDAP server
      Hashtable<String, String> env = new Hashtable<String, String>();
      env.put(LdapContext.CONTROL_FACTORIES,
              ldap.getProperty("factoriesControl"));
      env.put(Context.INITIAL_CONTEXT_FACTORY,
              ldap.getProperty("factoriesInitctx"));
      env.put(Context.PROVIDER_URL, ldap.getProperty("host"));
      if (ldap.containsKey("user")) {
        env.put(Context.SECURITY_PRINCIPAL, ldap.getProperty("user"));
      }
      if (ldap.containsKey("password")) {
        env.put(Context.SECURITY_CREDENTIALS, ldap.getProperty("password"));
      }
      DirContext  ctx = new InitialDirContext(env);

      // Zoeken naar gebruiker
      String          zoekUid   =
          MessageFormat.format(ldap.getProperty("userSearch"), login);
      String[]        attrIDs   = new String[]{"cn", "mail"};
      SearchControls  zoek      = new SearchControls();
      zoek.setReturningAttributes(attrIDs);
      zoek.setSearchScope(SearchControls.SUBTREE_SCOPE);
      NamingEnumeration<SearchResult>
                      antwoord  =
                        ctx.search(ldap.getProperty("userSearchbase"),
                                   zoekUid, zoek);
      if (!antwoord.hasMore()) {
        throw new LoginException(LOGIN_EXCEPTION);
      }
      SearchResult    sr        = (SearchResult) antwoord.next();
      if (antwoord.hasMore()) {
        throw new LoginException(LOGIN_EXCEPTION);
      }
      Attributes      attrs     = sr.getAttributes();
      String          cn        = attrs.get("cn").toString().substring(4);
      String          email     = attrs.get("mail").toString().substring(6);
      antwoord.close();
      // Sla de informatie op zodat die bij de commit kunnen worden vrij-
      // gegeven.
      userPrincipal = new UserPrincipal(login);
      userPrincipal.setEmail(email);
      userPrincipal.setVolledigeNaam(cn);
      if (debug) {
        logger.debug(userPrincipal.toString());
      }
      // Zoeken naar alle rollen.
      String  checkPassword = ldap.getProperty("checkPassword");
      String  principal     = "";
      if (checkPassword.startsWith("cn=")) {
        principal = MessageFormat.format(checkPassword, cn);
      } else {
        principal = MessageFormat.format(checkPassword, login);
      }
      env.put(Context.SECURITY_PRINCIPAL,   principal);
      env.put(Context.SECURITY_CREDENTIALS, password);
      ctx             = new InitialDirContext(env);
      zoekUid         = MessageFormat.format(ldap.getProperty("roleSearch"),
                                           login);
      attrIDs         = new String[]{"cn"};
      zoek            = new SearchControls();
      zoek.setReturningAttributes(attrIDs);
      zoek.setSearchScope(SearchControls.SUBTREE_SCOPE);
      antwoord        = ctx.search(ldap.getProperty("roleSearchbase"),
                                   zoekUid, zoek);
      rolePrincipals  = new ArrayList<RolePrincipal>();
      while (antwoord.hasMore()) {
        sr    = (SearchResult) antwoord.next();
        attrs = sr.getAttributes();
        rolePrincipals.add(new RolePrincipal(attrs.get("cn").toString()
                                                  .substring(4)));
      }

      antwoord.close();
      if (debug) {
        StringBuilder      rollen  = new StringBuilder();
        for (RolePrincipal rol : rolePrincipals) {
          rollen.append(", ").append(rol.toString());
        }
        logger.debug(rollen.toString().substring(2));
      }

      return true;
    } catch (IOException e) {
      logger.error(LOGIN_EXCEPTION, e);
      throw new LoginException(e.getMessage());
    } catch (UnsupportedCallbackException e) {
      logger.error(LOGIN_EXCEPTION, e);
      throw new LoginException(e.getMessage());
    } catch (NamingException e) {
      logger.error(LOGIN_EXCEPTION, e);
      throw new LoginException(e.getMessage());
    }
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
