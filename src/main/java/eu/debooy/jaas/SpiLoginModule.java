/**
 * Copyright 2017 Marco de Booij
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * you may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.debooy.jaas;

import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;


/**
 * @author Marco de Booij
 * 
 * Deze class implementeerd de basis methodes van de
 *  javax.security.auth.spi.LoginModule.
 * 
 * @see javax.security.auth.spi.LoginModule
 */
public class SpiLoginModule implements LoginModule {
  protected boolean             debug;
  protected CallbackHandler     handler;
  protected Properties          ldap;
  protected List<RolePrincipal> rolePrincipals;
  protected Subject             subject;
  protected UserPrincipal       userPrincipal;

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
  protected void clear() {
    this.rolePrincipals.clear();
    this.userPrincipal  = null;
  }

  public boolean commit() throws LoginException {
    if (null == userPrincipal) {
      return false;
    }

    subject.getPrincipals().add(userPrincipal);
    subject.getPrincipals().addAll(rolePrincipals);
    clear();

    return true;
  }

  public void initialize(Subject arg0, CallbackHandler arg1,
      Map<String, ?> arg2, Map<String, ?> arg3) {
  }

  public boolean login() throws LoginException {
    return false;
  }

  public boolean logout() throws LoginException {
    subject.getPrincipals().remove(userPrincipal);
    subject.getPrincipals().removeAll(rolePrincipals);
    clear();

    return true;
  }
}
