package com.baeldung.jwt.custom;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;
import org.springframework.stereotype.Component;

import com.baeldung.jwt.database.ConnectionFactory;
import com.baeldung.jwt.database.DbConnectionFactory;

@Component("registerUserStorageProviderFactory")
public class RegisterUserStorageProviderFactory implements UserStorageProviderFactory<RegisterUserStorageProvider> {

    @Override
    public RegisterUserStorageProvider create(KeycloakSession session, ComponentModel model) {

        String dbUrl = "jdbc:oracle:thin:@172.16.4.99:1521:saodb";
        String dbUser = "OAG_DEV";
        String dbPassword = "OAG_DEV";

        ConnectionFactory connectionFactory = new DbConnectionFactory(dbUrl, dbUser, dbPassword);

        return new RegisterUserStorageProvider(session, model, connectionFactory);
    }

    @Override
    public String getId() {
        return "register-user-provider";
    }
}
