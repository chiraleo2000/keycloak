package com.baeldung.jwt.custom;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import org.keycloak.storage.user.UserLookupProvider;

import com.baeldung.jwt.database.ConnectionFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class CustomUserStorageProvider implements UserStorageProvider, UserLookupProvider, CredentialInputValidator {

    private final KeycloakSession session;
    private final ComponentModel model;
    private final ConnectionFactory connectionFactory;

    public CustomUserStorageProvider(KeycloakSession session, ComponentModel model, ConnectionFactory connectionFactory) {
        this.session = session;
        this.model = model;
        this.connectionFactory = connectionFactory;
    }

    @Override
    public void close() {
        // Clean up resources if needed
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        String sql = "SELECT * FROM OAG_DEV.MDM_USER_INFO WHERE USER_INFO_ID = ?";
        try (Connection connection = connectionFactory.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
            statement.setString(1, id);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return createAdapter(realm, resultSet);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String idCard) {
        String sql = "SELECT * FROM OAG_DEV.MDM_USER_INFO WHERE ID_CARD = ?";
        try (Connection connection = connectionFactory.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
            statement.setString(1, idCard);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return createAdapter(realm, resultSet);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        String sql = "SELECT * FROM OAG_DEV.MDM_USER_INFO WHERE EMAIL = ?";
        try (Connection connection = connectionFactory.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
            statement.setString(1, email);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return createAdapter(realm, resultSet);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    private UserModel createAdapter(RealmModel realm, ResultSet resultSet) throws SQLException {

        String username = resultSet.getString("ID_CARD");
        String firstName = resultSet.getString("FIRST_NAME");
        String lastName = resultSet.getString("LAST_NAME");
        String email = resultSet.getString("EMAIL");

        return new AbstractUserAdapterFederatedStorage(session, realm, model) {
            @Override
            public String getUsername() {
                return username;
            }

            @Override
            public String getEmail() {
                return email;
            }

            @Override
            public String getFirstName() {
                return firstName;
            }

            @Override
            public String getLastName() {
                return lastName;
            }

            @Override
            public void setUsername(String idCard) {
                // Implement setting username if needed
            }
        };
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return CredentialModel.PASSWORD.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (supportsCredentialType(input.getType())) {
            String sql = "SELECT PASSWORD FROM OAG_DEV.MDM_USER_INFO WHERE ID_CARD = ?";
            try (Connection connection = connectionFactory.getConnection();
                 PreparedStatement statement = connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
                statement.setString(1, user.getUsername());
                try (ResultSet resultSet = statement.executeQuery()) {
                    if (resultSet.next()) {
                        String storedPassword = resultSet.getString("PASSWORD");
                        return input.getChallengeResponse().equals(storedPassword);
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return false;
    }
}
