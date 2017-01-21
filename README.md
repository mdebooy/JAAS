JAAS
====

Dit project bevat een eigen JAAS module. Het kan gebruik maken van een LDAP directory en hieruit het e-mail adres halen.

This project contains an own JAAS module. It can use an LDAP directory and fetch the e-mail address.

Configuratie
------------

###LDAP


    LdapLogin {
        eu.debooy.jaas.ldap.DoosLoginModule required
        checkPassword="cn={0},ou=People,dc=example,dc=com"
        debug=true
        factoriesControl="com.sun.jndi.ldap.ControlFactory"
        factoriesInitctx="com.sun.jndi.ldap.LdapCtxFactory"
        host="ldap://xxx.xxx.xxx.xxx:389"
        password="xxxxxxxx"
        roleSearch="memberUid={0}"
        roleSearchbase="ou=Roles,dc=example,dc=com"
        user="cn=xxxxxxxx,dc=example,dc=com"
        userSearch="uid={0}"
        userSearchbase="ou=People,dc=example,dc=com";
    };

###Properties

    PropertiesLogin {
        eu.debooy.jaas.properties.DoosLoginModule required
        debug=true
        UsersFile=users.properties
        GroupsFile=groups.properties;
    };

In het `users.properties` bestand zijn er 3 velden gescheiden door een 'tab'. Deze velden zijn:

0. wachtwoord
0. naam van de persoon
0. e-mail adres

Er moet minstens 1 veld (wachtwoord) zijn.