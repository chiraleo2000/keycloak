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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class RegisterUserStorageProvider implements UserStorageProvider, UserLookupProvider, CredentialInputValidator {

    private final KeycloakSession session;
    private final ComponentModel model;
    private final ConnectionFactory connectionFactory;

    public RegisterUserStorageProvider(KeycloakSession session, ComponentModel model, ConnectionFactory connectionFactory) {
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
        String sql = "SELECT * FROM OAG_DEV.CMS_REGISTER WHERE REGISTER_ID = ?";
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
    public UserModel getUserByUsername(RealmModel realm, String userName) {
        String sql = "SELECT * FROM OAG_DEV.CMS_REGISTER WHERE REGISTER_USER_NAME = ?";
        try (Connection connection = connectionFactory.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
            statement.setString(1, userName);
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
        String sql = "SELECT * FROM OAG_DEV.CMS_REGISTER WHERE REGISTER_USER_NAME = ?";
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

        String username = resultSet.getString("REGISTER_USER_NAME");
        String firstName = resultSet.getString("PERSONAL_FNAME_THA");
        String lastName = resultSet.getString("PERSONAL_LNAME_THA");
        String email = resultSet.getString("PERSONAL_EMAIL");

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
            public void setUsername(String userName) {
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
            String sql = "SELECT REGISTER_PASSWORD FROM OAG_DEV.CMS_REGISTER WHERE REGISTER_USER_NAME = ?";
            try (Connection connection = connectionFactory.getConnection();
                PreparedStatement statement = connection.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
                statement.setString(1, user.getUsername());
                try (ResultSet resultSet = statement.executeQuery()) {
                    if (resultSet.next()) {
                        String storedPassword = resultSet.getString("REGISTER_PASSWORD");
                        String hashedInputPassword = hashPassword(input.getChallengeResponse());
                        
                        return hashedInputPassword.equals(storedPassword);
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
            for (byte b : encodedHash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
}

