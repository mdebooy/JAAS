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
package eu.debooy.jaas;

import java.security.Principal;

import org.apache.openejb.spi.CallerPrincipal;


/**
 * @author Marco de Booij
 * 
 * Uitbreiding van de java.security.Principal die ook de volledige naam en
 * het e-mail adres van de gebruiker bevat.
 * 
 * @see java.security.Principal
 */
@CallerPrincipal
public class UserPrincipal implements Principal {
  private String  email;
  private String  name;
  private String  volledigeNaam;
  
  // Constructor met enkel de name van het login scherm.
  public UserPrincipal(String name) {
    super();
    this.name = name;
  }

  @Override
  public boolean equals(Object object) {
    if (!(object instanceof UserPrincipal)) {
      return false;
    }

    final UserPrincipal userPrincipal = (UserPrincipal) object;

    return name.equals(userPrincipal.name);
  }

  /**
   * @return het e-mail adres
   */
  public String getEmail() {
    return email;
  }

  /**
   * @return de name (login)
   */
  public String getName() {
    return name;
  }

  @Override
  public int hashCode() {
    return name.hashCode();
  }

  /**
   * @return de volledige naam
   */
  public String getVolledigeNaam() {
    return volledigeNaam;
  }

  /**
   * @param email de waarde van email
   */
  public void setEmail(String email) {
    this.email  = email;
  }

  /**
   * @param name de waarde van name
   */
  public void setName(String name) {
    this.name = name;
  }

  /**
   * @param volledigeNaam de waarde van volledigeNaam
   */
  public void setVolledigeNaam(String volledigeNaam) {
    this.volledigeNaam = volledigeNaam;
  }

  @Override
  public String toString() {
    return "email=[" + email + "], name=[" + name + "], volledigenaam=["
           + volledigeNaam +"]";
  }
}
