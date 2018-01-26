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
import java.util.EnumSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.google.common.collect.ImmutableList;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.X509IdentityValidator;
import org.eclipse.milo.opcua.stack.core.application.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.application.DefaultCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.util.CryptoRestrictions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.google.common.collect.Lists.newArrayList;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_USERNAME;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_X509;


public class SecureServerStandalone {

    private static final String APPLICATION_NAME = "Eclipse Milo OPC-UA Example Server";

    private static final String APPLICATION_URI = "urn:eclipse:milo:examples:server";

    private String ip = System.getenv("OPCUA_SERVER_IP");

    private static final Logger logger = LoggerFactory.getLogger(SecureServerStandalone.class);

    private final OpcUaServer server;

    public static void main(String[] args) {
        SecureServerStandalone server = new SecureServerStandalone();

        try {
            server.startup().get();
        } catch (InterruptedException i) {
            logger.error("Starting up the server was interrupted.", i);
            System.exit(1);
        } catch (ExecutionException e) {
            logger.error("Concurrency problems encountered during startup", e);
        }



        final CompletableFuture<Void> future = new CompletableFuture<>();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> future.complete(null)));

        try {
            future.get();
        } catch (InterruptedException i) {
            logger.error("Running the server was interrupted.", i);
            System.exit(1);
        } catch (ExecutionException e) {
            logger.error("Concurrency problems encountered", e);
        }
    }

    public SecureServerStandalone() {
        CryptoRestrictions.remove();

        File securityTempDir = new File(System.getenv("OPCUA_CERT_DIR"), "security");

        logger.info("security temp dir: {}", securityTempDir.getAbsolutePath());

        KeyStoreLoader loader = new KeyStoreLoader();
        try {
            loader = loader.load(securityTempDir);
        } catch (Exception e) {
            logger.error("Could not aquire KeyStoreLoader.", e);
        }

        DefaultCertificateManager certificateManager = new DefaultCertificateManager(
            loader.getServerKeyPair(),
            loader.getServerCertificate()
        );

        DefaultCertificateValidator certificateValidator = new DefaultCertificateValidator(securityTempDir);

        X509IdentityValidator x509identityValidator = new X509IdentityValidator(c -> true);

        OpcUaServerConfig serverConfig = OpcUaServerConfig.builder()
            .setApplicationUri(APPLICATION_URI)
            .setApplicationName(LocalizedText.english(APPLICATION_NAME))
            .setBindAddresses(newArrayList(ip))
            .setBindPort(4840)
            .setBuildInfo(
                new BuildInfo(
                    "urn:eclipse:milo:example-server",
                    "eclipse",
                    "eclipse milo example server",
                    OpcUaServer.SDK_VERSION,
                    "", DateTime.now()))
            .setCertificateManager(certificateManager)
            .setCertificateValidator(certificateValidator)
            .setIdentityValidator(x509identityValidator)
            .setProductUri("urn:eclipse:milo:example-server")
            .setSecurityPolicies(
                EnumSet.of(
                    SecurityPolicy.Basic128Rsa15,
                    SecurityPolicy.Basic256,
                    SecurityPolicy.Basic256Sha256))
            .setUserTokenPolicies(
                ImmutableList.of(
                    USER_TOKEN_POLICY_USERNAME,
                    USER_TOKEN_POLICY_X509))
            .build();

        server = new OpcUaServer(serverConfig);

        server.getNamespaceManager().registerAndAdd(
            ExampleNamespace.NAMESPACE_URI,
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