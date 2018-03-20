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

package org.eclipse.milo.examples.client;

import java.io.File;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableList;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.api.identity.IdentityProvider;
import org.eclipse.milo.opcua.sdk.client.api.identity.UsernameProvider;
import org.eclipse.milo.opcua.sdk.client.api.nodes.VariableNode;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.client.UaTcpStackClient;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.Stack;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ServerState;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.util.CryptoRestrictions;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

public class ClientWithUserNameAndPasswordExample {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final Pattern IP_ADDR_PATTERN = Pattern.compile(
            "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
    private static final String EXAMPLE_USERNAME = System.getenv("USERNAME");
    private static final String EXAMPLE_PASSWORD = System.getenv("PASSWORD");
    private static final String ENDPOINT_URL = System.getenv("ENDPOINT_URL");

    private final CompletableFuture<OpcUaClient> future = new CompletableFuture<>();

    public static void main(String[] args) throws Exception {
        if (EXAMPLE_USERNAME == null || EXAMPLE_PASSWORD == null) {
            throw new RuntimeException("Username and/or password for example could not be read");
        }
        ClientWithUserNameAndPasswordExample example = new ClientWithUserNameAndPasswordExample();
        example.run();
    }

    private OpcUaClient createClient() throws Exception {
        SecurityPolicy securityPolicy = SecurityPolicy.None;

        EndpointDescription[] endpoints;
        try {
            endpoints = UaTcpStackClient
                    .getEndpoints(ENDPOINT_URL)
                    .get();
        } catch (Throwable ex) {
            // try the explicit discovery endpoint as well
            String discoveryUrl = ENDPOINT_URL + "/discovery";
            logger.info("Trying explicit discovery URL: {}", discoveryUrl);
            endpoints = UaTcpStackClient
                    .getEndpoints(discoveryUrl)
                    .get();
        }

        EndpointDescription endpoint = Arrays.stream(endpoints)
                .filter(e -> e.getSecurityPolicyUri().equals(securityPolicy.getSecurityPolicyUri()))
                .findFirst().orElseThrow(() -> new Exception("no desired endpoints returned"));

        logger.info("Using endpoint: {} [{}]", endpoint.getEndpointUrl(), securityPolicy);

        KeyPair keyPair = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);

        SelfSignedCertificateBuilder builder = new SelfSignedCertificateBuilder(keyPair)
                .setCommonName("Eclipse Milo Example Client")
                .setOrganization("digitalpetri")
                .setOrganizationalUnit("dev")
                .setLocalityName("Folsom")
                .setStateName("CA")
                .setCountryCode("US")
                .setApplicationUri("urn:eclipse:milo:examples:client")
                .addDnsName("localhost")
                .addIpAddress("127.0.0.1");

        // Get as many hostnames and IP addresses as we can listed in the certificate.
        for (String hostname : HostnameUtil.getHostnames("0.0.0.0")) {
            if (IP_ADDR_PATTERN.matcher(hostname).matches()) {
                builder.addIpAddress(hostname);
            } else {
                builder.addDnsName(hostname);
            }
        }

        X509Certificate certificate = builder.build();
        OpcUaClientConfig config = OpcUaClientConfig.builder()
                .setApplicationName(LocalizedText.english("eclipse milo opc-ua client"))
                .setApplicationUri("urn:eclipse:milo:examples:client")
                .setCertificate(certificate)
                .setKeyPair(keyPair)
                .setEndpoint(endpoint)
                .setIdentityProvider(getIdentityProvider())
                .setRequestTimeout(uint(5000))
                .build();

        return new OpcUaClient(config);
    }


    private CompletableFuture<List<DataValue>> readServerStateAndTime(OpcUaClient client) {
        List<NodeId> nodeIds = ImmutableList.of(
            Identifiers.Server_ServerStatus_State,
            Identifiers.Server_ServerStatus_CurrentTime);

        return client.readValues(0.0, TimestampsToReturn.Both, nodeIds);
    }

    public IdentityProvider getIdentityProvider() {
        return new UsernameProvider(EXAMPLE_USERNAME, EXAMPLE_PASSWORD);
    }

    public void run() {
        try {
            OpcUaClient client = createClient();

            future.whenComplete((c, ex) -> {
                if (ex != null) {
                    logger.error("Error running example: {}", ex.getMessage(), ex);
                }

                try {
                    client.disconnect().get();
                    Stack.releaseSharedResources();
                } catch (InterruptedException | ExecutionException e) {
                    logger.error("Error disconnecting:", e.getMessage(), e);
                }

                try {
                    Thread.sleep(1000);
                    System.exit(0);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            });

            try {
                client.connect().get();

                // synchronous read request via VariableNode
                VariableNode node = client.getAddressSpace()
                        .createVariableNode(Identifiers.Server_ServerStatus_StartTime);
                DataValue value = node.readValue().get();

                logger.info("StartTime={}", value.getValue().getValue());

                // asynchronous read request
                readServerStateAndTime(client).thenAccept(values -> {
                    DataValue v0 = values.get(0);
                    DataValue v1 = values.get(1);

                    logger.info("State={}", ServerState.from((Integer) v0.getValue().getValue()));
                    logger.info("CurrentTime={}", v1.getValue().getValue());

                    future.complete(client);
                });
                future.get(15, TimeUnit.SECONDS);
            } catch (Throwable t) {
                logger.error("Error running client example: {}", t.getMessage(), t);
                future.completeExceptionally(t);
            }
        } catch (Throwable t) {
            logger.error("Error getting client: {}", t.getMessage(), t);

            future.completeExceptionally(t);

            try {
                Thread.sleep(1000);
                System.exit(0);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        try {
            Thread.sleep(999999999);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    static {
        CryptoRestrictions.remove();
        // Required for SecurityPolicy.Aes256_Sha256_RsaPss
        Security.addProvider(new BouncyCastleProvider());
    }

}
