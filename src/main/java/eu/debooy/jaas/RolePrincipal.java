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


/**
 * @author Marco de Booij
 * 
 * @see java.security.Principal
 */
public class RolePrincipal implements Principal {
  private String  name;
  
  // Constructor met enkel de name van de role.
  public RolePrincipal(String name) {
    super();
    this.name = name;
  }

  @Override
  public boolean equals(Object object) {
    if (!(object instanceof RolePrincipal)) {
      return false;
    }

    final RolePrincipal rolePrincipal = (RolePrincipal) object;

    return name.equals(rolePrincipal.name);
  }

  /**
   * @return de name (role)
   */
  public String getName() {
    return name;
  }

  @Override
  public int hashCode() {
    return name.hashCode();
  }

  /**
   * @param name de waarde van name
   */
  public void setName(String name) {
    this.name = name;
  }
}
