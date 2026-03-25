/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.1.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.1.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 Wren Security.
 */

package org.wrensecurity.test.wrenidm.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.testcontainers.containers.ComposeContainer;
import org.wrensecurity.test.wrenidm.base.BaseWrenidmTest;
import tools.jackson.databind.node.ObjectNode;

@TestInstance(Lifecycle.PER_CLASS)
public class AuthenticationTest extends BaseWrenidmTest {

    public static String TEST_USER_DATA = """
            {
              "userName": "jdoe",
              "givenName": "John",
              "sn": "Doe",
              "mail": "john.doe@example.com",
              "accountStatus": "active"
            }
            """;

    @BeforeAll
    public void init() {
        environment = new ComposeContainer(new File("src/test/resources/cases/authentication/compose.yaml"));
        environment.waitingFor(WRENIDM_CONTAINER_NAME, WRENIDM_STARTUP_WAIT_STRATEGY);
        environment.start();
    }

    @AfterAll
    public void teardown() {
        if (environment != null) {
            environment.stop();
        }
    }

    @Test
    public void testClientCert() throws Exception {
        HttpRequest sendReq = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user"))
                .header("Authorization", "Basic " + Base64.getEncoder()
                        .encodeToString("openidm-admin:openidm-admin".getBytes()))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(TEST_USER_DATA))
                .build();
        HttpResponse<String> sendResp = httpClient.send(sendReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, sendResp.statusCode());


        HttpClient client = createHttpsClient("jdoe");

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://wrenidm.wrensecurity.local:8444/openidm/info/login"))
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertEquals("CN=jdoe, OU=Users, O=Wren Security", mapper.readValue(response.body(), ObjectNode.class)
                .get("authenticationId").stringValue());
    }

    private HttpClient createHttpsClient(String username) throws Exception {
        SSLContext sslContext = createSslContext(username);

        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .build();
    }

    private SSLContext createSslContext(String username) throws Exception {
        String keyStorePath = "/cases/authentication/mtls/user-" + username + ".p12";

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = getClass().getResourceAsStream(keyStorePath)) {
            keyStore.load(input, "changeit".toCharArray());
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, "changeit".toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[] { new TrustAllManager() }, null);

        return sslContext;
    }

    private static final class TrustAllManager extends X509ExtendedTrustManager {

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
        }

    }

}
