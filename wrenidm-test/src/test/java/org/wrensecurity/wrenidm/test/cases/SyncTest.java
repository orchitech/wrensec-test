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
package org.wrensecurity.wrenidm.test.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.wrensecurity.wrenidm.test.base.BaseWrenidmTest;
import tools.jackson.databind.JsonNode;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SyncTest extends BaseWrenidmTest {

    private static final String MANAGED_USER_DATA = """
        {
          "userName": "sync2",
          "givenName": "John",
          "sn": "Doe",
          "mail": "john.doe@wrensecurity.org",
          "telephoneNumber": "5554567",
          "password":"FooBar123"
        }
        """;

    private final HttpWaitStrategy LDAP_PROVISIONER_WAIT_STRATEGY = Wait
            .forHttp("/openidm/system/ldap?_action=test")
            .withHeader("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .forStatusCode(200)
            .withReadTimeout(Duration.ofMinutes(5));

    private String reconId;

    @BeforeAll
    public void init() throws Exception {
        environment = new ComposeContainer(new File("src/test/resources/cases/sync/compose.yaml"));
        environment.waitingFor(WRENIDM_CONTAINER_NAME, WRENIDM_STARTUP_WAIT_STRATEGY);
        environment.start();
        environment.waitingFor(WRENIDM_CONTAINER_NAME, LDAP_PROVISIONER_WAIT_STRATEGY);
    }

    @AfterAll
    public void teardown() {
        if (environment != null) {
            environment.stop();
        }
    }

    @Test
    @Order(1)
    public void testSetup() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user/sync2"))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(MANAGED_USER_DATA))
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, resp.statusCode());
    }

    @Test
    @Order(2)
    public void testSourceReconciliation() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(WRENIDM_BASE_URL + "/openidm/recon?_action=recon&mapping=csvEmployee_managedUser&waitForCompletion=true"))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        JsonNode body = mapper.readTree(resp.body());
        assertEquals("SUCCESS", body.get("state").asString());
        reconId = body.get("_id").asString();
    }

    @Test
    @Order(3)
    public void testReconciliationResult() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(WRENIDM_BASE_URL + "/openidm/recon/" + reconId))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        JsonNode body = mapper.readTree(resp.body());
        JsonNode summary = body.get("situationSummary");
        assertEquals(1, summary.get("ABSENT").asInt());
        assertEquals(1, summary.get("FOUND").asInt());
        assertEquals(1, summary.get("SOURCE_IGNORED").asInt());
    }

    @Test
    @Order(4)
    public void testQueryManagedUsers() throws Exception {
        String encodedFilter = URLEncoder.encode("/userName sw \"sync\"", StandardCharsets.UTF_8);
        HttpRequest req = HttpRequest.newBuilder(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user?_queryFilter=" + encodedFilter))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        JsonNode body = mapper.readTree(resp.body());
        assertEquals(2, body.get("resultCount").asInt());

        JsonNode result = body.get("result");
        assertTrue(result.get(0).get("_id").asString().matches("^sync(1|2)$"));
        assertTrue(result.get(1).get("_id").asString().matches("^sync(1|2)$"));
    }

    @Test
    @Order(5)
    public void testImplicitSync() throws Exception {
        String filter = URLEncoder.encode(
                "/mapping eq \"managedUser_ldapAccount\" and " +
                "/sourceObjectId sw \"managed/user/sync\" and " +
                "/status eq \"SUCCESS\"", StandardCharsets.UTF_8);

        int attempts = 100;

        while (--attempts > 0) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(WRENIDM_BASE_URL + "/openidm/audit/sync?_queryFilter=" + filter))
                    .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, resp.statusCode());

            JsonNode body = mapper.readTree(resp.body());
            if (body.path("resultCount").asInt() == 2) {
                return;
            }

            Thread.sleep(1000);
        }

        fail("Implicit synchronization to LDAP failed.");
    }

    @Test
    @Order(6)
    public void testLdapAccounts() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(WRENIDM_BASE_URL + "/openidm/system/ldap/account?_queryId=query-all-ids"))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        JsonNode body = mapper.readTree(resp.body());
        assertEquals(2, body.get("resultCount").asInt());

        JsonNode result = body.get("result");
        assertTrue(result.get(0).get("_id").asString().matches("^uid=sync(1|2),dc=wrensecurity,dc=org$"));
        assertTrue(result.get(1).get("_id").asString().matches("^uid=sync(1|2),dc=wrensecurity,dc=org$"));
    }
}
