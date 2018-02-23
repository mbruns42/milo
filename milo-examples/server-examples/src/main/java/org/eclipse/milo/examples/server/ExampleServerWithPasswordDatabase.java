/*
 * Copyright (c) 2016 Kevin Herron
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *   http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.html.
 */

package org.eclipse.milo.examples.server;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

import com.google.common.collect.ImmutableList;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.application.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.application.DirectoryCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil;
import org.eclipse.milo.opcua.stack.core.util.CryptoRestrictions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.google.common.collect.Lists.newArrayList;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_USERNAME;

public class ExampleServerWithPasswordDatabase {

    private File securityTempDir = new File(System.getProperty(JAVA_IO_TMPDIR), SECURITY);
    private File baseDbDir;
    private File trustedDbDir;
    private File rejectedDbDir;
    private File trustedUserDatabase;
    private File rejectedUserDatabase;

    // FOLDER NAMES
    private static final String JAVA_IO_TMPDIR = "java.io.tmpdir";
    private static final String SECURITY = "security";
    private static final String PKI_DIR = "pki";
    private static final String BASE_DB_DIR = "db";
    private static final String TRUSTED_DB_DIR = "trusted";
    private static final String REJECTED_DB_DIR = "rejected";

    // OPC UA MILO PROPERTIES
    private static final String _0_0_0_0 = "0.0.0.0";
    private static final String ECLIPSE_MILO_OPC_UA_EXAMPLE_SERVER = "Eclipse Milo OPC UA Example Server";
    private static final String ECLIPSE_MILO_EXAMPLE_SERVER = "eclipse milo example server";
    private static final String ECLIPSE = "eclipse";
    private static final String EXAMPLE = "example";
    private static final String URN_ECLIPSE_MILO_EXAMPLES_SERVER = "urn:eclipse:milo:examples:server:";
    private static final String PRODUCT_URI = "urn:eclipse:milo:example-server";

    // DATABASE PROPERTIES
    private static final String JDBC_SQLITE = "jdbc:sqlite:";
    private static final String USERS_DB = "Users.db";
    private static final String DATABASE_PASSWORD_COLUMN = "Password";
    private static final String DATABASE_USER_COLUMN = "Username";
    private static final String DATABASE_NAME = "Users";

    // LOGGER SECURITY DATABASE STATUS
    private static final String PASSWORD_IS_CORRECT = "Password is correct.";
    private static final String FOUND_USER_IN_DATABASE = "Found user in database.";

    // LOGGER DATABASE STATUS
    private static final String PROBLEM_CLOSING_USER_DATABASE = "Problem closing user database";
    private static final String PROBLEM_ACCESSING_USER_DATABASE = "Problem accessing user database";
    private static final String CONNECTED_TO_USER_DATABASE = "Connected to user database";
    private static final String DATABASE_FOUND = "Database found {}";

    // LOGGER FOLDER AND FILE STATUS
    private static final String PKI_DIR_LOG = "pki dir: {}";
    private static final String DB_DIR_LOG = "db dir: {}";
    private static final String NO_USER_DATABASE = "No database file: ";
    private static final String UNABLE_TO_CREATE_SECURITY_TEMP_DIR = "unable to create security temp dir: ";
    private static final String NO_SECURITY_TEMP_DIR = "No security temp dir: ";
    private static final String SECURITY_TEMP_DIR = "security temp dir: {}";

    // LOGGER SQL ERRORS
    private static final String SQL_STATEMENT = "SQL Statement: ";

    // LOGGER OPC UA SECURITY ERRORS
    private static final String CERTIFICATE_IS_MISSING_THE_APPLICATION_URI = "certificate is missing "
            + "the application URI";

    Logger logger = LoggerFactory.getLogger(this.getClass());

    static {
        CryptoRestrictions.remove();

        // Required for SecurityPolicy.Aes256_Sha256_RsaPss
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        ExampleServerWithPasswordDatabase server = new ExampleServerWithPasswordDatabase();

        server.startup().get();

        final CompletableFuture<Void> future = new CompletableFuture<>();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> future.complete(null)));

        future.get();
    }

    public File getTrustedDbDir() {
        return trustedDbDir;
    }

    public File getBaseDbDir() {
        return baseDbDir;
    }

    public File getRejectedDbDir() {
        return rejectedDbDir;
    }

    private final OpcUaServer server;

    public ExampleServerWithPasswordDatabase() throws Exception {
        File securityTempDir = new File(System.getProperty(JAVA_IO_TMPDIR), SECURITY);
        if (!securityTempDir.exists() && !securityTempDir.mkdirs()) {
            throw new Exception(UNABLE_TO_CREATE_SECURITY_TEMP_DIR + securityTempDir.getAbsolutePath());
        }
        logger.info(SECURITY_TEMP_DIR, securityTempDir.getAbsolutePath());

        baseDbDir = securityTempDir.toPath().resolve(BASE_DB_DIR).toFile();
        if (!baseDbDir.exists() && !baseDbDir.mkdirs()) {
            logger.info("unable to create directory at " + baseDbDir.getAbsolutePath());
            throw new IOException("unable to create directory at " + baseDbDir.getAbsolutePath());
        } else {
            logger.info("Base Database dir: {}", baseDbDir.getAbsolutePath());
            trustedDbDir = baseDbDir.toPath().resolve(TRUSTED_DB_DIR).toFile();
            if (!trustedDbDir.exists() && !trustedDbDir.mkdirs()) {
                logger.info("unable to create directory at " + trustedDbDir.getAbsolutePath());
                throw new IOException("unable to create directory at " + trustedDbDir.getAbsolutePath());
            }
            logger.info("Trusted Database dir: {}", trustedDbDir.getAbsolutePath());
            rejectedDbDir = baseDbDir.toPath().resolve(REJECTED_DB_DIR).toFile();
            if (!rejectedDbDir.exists() && !rejectedDbDir.mkdirs()) {
                logger.info("unable to create directory at " + rejectedDbDir.getAbsolutePath());
                throw new IOException("unable to create directory at " + rejectedDbDir.getAbsolutePath());
            }
            rejectedUserDatabase = rejectedDbDir.toPath().resolve(USERS_DB).toFile();
            if (!rejectedUserDatabase.exists()) {
                rejectedUserDatabase.createNewFile();
            }
            logger.info("Rejected Database dir: {}", rejectedDbDir.getAbsolutePath());

        }
        trustedUserDatabase = trustedDbDir.toPath().resolve(USERS_DB).toFile();
        if (!trustedUserDatabase.exists()) {
            logger.debug(NO_USER_DATABASE + trustedUserDatabase);
            throw new IOException("unable to find user database at " + trustedUserDatabase.getAbsolutePath());
        }

        KeyStoreLoader loader = new KeyStoreLoader().load(securityTempDir);

        DefaultCertificateManager certificateManager = new DefaultCertificateManager(loader.getServerKeyPair(),
                loader.getServerCertificateChain());

        File pkiDir = securityTempDir.toPath().resolve(PKI_DIR).toFile();
        DirectoryCertificateValidator certificateValidator = new DirectoryCertificateValidator(pkiDir);
        logger.info(PKI_DIR_LOG, pkiDir.getAbsolutePath());

        Predicate<UsernameIdentityValidator.AuthenticationChallenge> authPredicate = authenticationChallenge -> {

            if (!securityTempDir.exists()) {
                logger.debug(NO_SECURITY_TEMP_DIR + securityTempDir);
                return false;
            }

            if (!trustedUserDatabase.exists()) {
                logger.debug(NO_USER_DATABASE + trustedUserDatabase);
                return false;
            }
            logger.info(DATABASE_FOUND, trustedUserDatabase.getAbsolutePath());

            logger.info(DB_DIR_LOG, baseDbDir.getAbsolutePath());

            Connection trustedConnnection = null;
            Connection rejectedConnnection = null;
            PreparedStatement pstmt = null;
            Statement stmt = null;

            try {
                // Argon2, the password-hashing function that won the Password Hashing Competition (PHC).
                // Source: https://github.com/phxql/argon2-jvm
                Argon2 argon2 = Argon2Factory.create();
                String trustedDatabaseUrl = JDBC_SQLITE + trustedUserDatabase.getAbsolutePath();
                trustedConnnection = DriverManager.getConnection(trustedDatabaseUrl);
                logger.info(CONNECTED_TO_USER_DATABASE);

                // https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet
                // Prepared Statements (with Parameterized Queries)
                String sql = "SELECT " + DATABASE_PASSWORD_COLUMN + " FROM " + DATABASE_NAME + " WHERE "
                        + DATABASE_USER_COLUMN + "=?";
                String custname = authenticationChallenge.getUsername();
                pstmt = trustedConnnection.prepareStatement(sql);
                pstmt.setString(1, custname);
                ResultSet rs = pstmt.executeQuery();
                logger.info(SQL_STATEMENT + sql);

                if (!rs.next()) {
                    try {
                        String rejectedDatabaseUrl = JDBC_SQLITE + rejectedUserDatabase.getAbsolutePath();
                        rejectedConnnection = DriverManager.getConnection(rejectedDatabaseUrl);
                        logger.info(CONNECTED_TO_USER_DATABASE);
                        if (rejectedConnnection != null) {
                            DatabaseMetaData meta = rejectedConnnection.getMetaData();
                            logger.info("Successfully created database:" + meta.getDriverName());
                        } else {
                            return false;
                        }

                        // CREATE TABLE ONLY IF IT DOES NOT EXIST
                        sql = "CREATE TABLE IF NOT EXISTS " + DATABASE_NAME + " ( " + DATABASE_USER_COLUMN
                                + " TEXT not NULL, " + DATABASE_PASSWORD_COLUMN + " TEXT not NULL, " + " PRIMARY KEY ('"
                                + DATABASE_USER_COLUMN + "'))";
                        stmt = rejectedConnnection.createStatement();
                        stmt.executeUpdate(sql);
                        logger.info("Successfully created table");

                        // INSERT USERNAME AND HASHED PASSWORD INTO REJECTED DATABASE
                        sql = "INSERT INTO " + DATABASE_NAME + " (" + DATABASE_USER_COLUMN + ","
                                + DATABASE_PASSWORD_COLUMN + ")" + "VALUES (?,?)";
                        pstmt = rejectedConnnection.prepareStatement(sql);
                        pstmt.setString(1, custname);
                        pstmt.setString(2, argon2.hash(2, 65536, 1, authenticationChallenge.getPassword()));
                        pstmt.executeUpdate();
                        logger.info("Successfully inserted user into rejected table");

                    } catch (SQLException se) {
                        se.printStackTrace();
                    }
                    return false;
                } else {
                    logger.info(FOUND_USER_IN_DATABASE);
                }

                // verify hashes the password and compare it to the hashed password from the database
                // The hash includes the salt. The verify method extracts the salt from the hash and uses that.
                // (https://github.com/phxql/argon2-jvm/issues/19)
                if (argon2.verify(rs.getString(DATABASE_PASSWORD_COLUMN), authenticationChallenge.getPassword())) {
                    logger.info(PASSWORD_IS_CORRECT);
                    return true;
                }

            } catch (SQLException e) {
                logger.error(PROBLEM_ACCESSING_USER_DATABASE, e);
                return false;

            } finally {
                try {
                    if (trustedConnnection != null) {
                        trustedConnnection.close();
                    }
                    if (rejectedConnnection != null) {
                        rejectedConnnection.close();
                    }
                } catch (SQLException ex) {
                    logger.error(PROBLEM_CLOSING_USER_DATABASE, ex);
                }
            }

            return false;
        };

        UsernameIdentityValidator identityValidator = new UsernameIdentityValidator(false, authPredicate);

        List<String> bindAddresses = newArrayList();
        bindAddresses.add(_0_0_0_0);

        List<String> endpointAddresses = newArrayList();
        endpointAddresses.add(HostnameUtil.getHostname());
        endpointAddresses.addAll(HostnameUtil.getHostnames(_0_0_0_0));

        // The configured application URI must match the one in the certificate(s)
        String applicationUri = certificateManager.getCertificates().stream().findFirst()
                .map(certificate -> CertificateUtil
                        .getSubjectAltNameField(certificate, CertificateUtil.SUBJECT_ALT_NAME_URI).map(Object::toString)
                        .orElseThrow(() -> new RuntimeException(CERTIFICATE_IS_MISSING_THE_APPLICATION_URI)))
                .orElse(URN_ECLIPSE_MILO_EXAMPLES_SERVER + UUID.randomUUID());

        OpcUaServerConfig serverConfig = OpcUaServerConfig.builder().setApplicationUri(applicationUri)
                .setApplicationName(LocalizedText.english(ECLIPSE_MILO_OPC_UA_EXAMPLE_SERVER)).setBindPort(12686)
                .setBindAddresses(bindAddresses).setEndpointAddresses(endpointAddresses)
                .setBuildInfo(new BuildInfo(PRODUCT_URI, ECLIPSE, ECLIPSE_MILO_EXAMPLE_SERVER, OpcUaServer.SDK_VERSION,
                        "", DateTime.now()))
                .setCertificateManager(certificateManager).setCertificateValidator(certificateValidator)
                .setIdentityValidator(identityValidator).setProductUri(PRODUCT_URI).setServerName(EXAMPLE)
                .setSecurityPolicies(EnumSet.of(SecurityPolicy.None, SecurityPolicy.Basic128Rsa15,
                        SecurityPolicy.Basic256, SecurityPolicy.Basic256Sha256, SecurityPolicy.Aes128_Sha256_RsaOaep,
                        SecurityPolicy.Aes256_Sha256_RsaPss))
                .setUserTokenPolicies(ImmutableList.of(USER_TOKEN_POLICY_USERNAME)).build();

        server = new OpcUaServer(serverConfig);

        server.getNamespaceManager().registerAndAdd(ExampleNamespace.NAMESPACE_URI,
                idx -> new ExampleNamespace(server, idx));
    }

    public OpcUaServer getServer() {
        return server;
    }

    public CompletableFuture<OpcUaServer> startup() {
        return server.startup();
    }

    public CompletableFuture<OpcUaServer> shutdown() {
        return server.shutdown();
    }

}
