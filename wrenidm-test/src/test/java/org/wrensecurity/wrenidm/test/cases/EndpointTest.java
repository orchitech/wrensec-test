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

import java.io.File;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;
import org.testcontainers.containers.ComposeContainer;
import org.wrensecurity.wrenidm.test.base.BaseWrenidmTest;
import tools.jackson.databind.JsonNode;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class EndpointTest extends BaseWrenidmTest {

    private static final String MANAGED_USER_DATA = """
        {
          "userName": "endpoint",
          "givenName": "John",
          "sn": "Doe",
          "mail": "doe@wrensecurity.org",
          "password":"Password1"
        }
        """;

    @BeforeAll
    public void init() {
        environment = new ComposeContainer(new File("src/test/resources/cases/endpoint/compose.yaml"));
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
    @Order(1)
    public void testSetup() throws Exception {
        HttpRequest createUserReq = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user/endpoint"))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(MANAGED_USER_DATA))
                .build();
        HttpResponse<String> createUserResp = httpClient.send(createUserReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, createUserResp.statusCode());
    }

    @Test
    @Order(2)
    public void testDefaultEndpoint() throws Exception {
        HttpRequest queryReq = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user?_queryFilter=/userName%20eq%20%22endpoint%22"))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .build();
        HttpResponse<String> queryResp = httpClient.send(queryReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, queryResp.statusCode());

        JsonNode responseBody = mapper.readTree(queryResp.body());
        assertEquals(1, responseBody.get("resultCount").asInt());
        assertEquals("endpoint", responseBody.get("result").get(0).get("_id").asString());
    }

    @Test
    @Order(3)
    public void testCustomEndpoint() throws Exception {
        HttpRequest queryReq = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/endpoint/custom/users?_queryId=dummy"))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .build();
        HttpResponse<String> queryResp = httpClient.send(queryReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, queryResp.statusCode());

        JsonNode responseBody = mapper.readTree(queryResp.body());
        assertEquals(1, responseBody.get("resultCount").asInt());
        assertEquals("endpoint", responseBody.get("result").get(0).get("_id").asString());
    }

}
