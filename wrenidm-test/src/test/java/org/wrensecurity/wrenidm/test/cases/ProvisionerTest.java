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

import java.io.File;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.wrensecurity.wrenidm.test.base.BaseWrenidmTest;
import tools.jackson.databind.JsonNode;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ProvisionerTest extends BaseWrenidmTest {

    private final HttpWaitStrategy LDAP_PROVISIONER_WAIT_STRATEGY = Wait
            .forHttp("/openidm/system/ldap?_action=test")
            .withHeader("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .forStatusCode(200)
            .withReadTimeout(Duration.ofMinutes(5));

    @BeforeAll
    public void init() throws Exception {
        environment = new ComposeContainer(new File("src/test/resources/cases/provisioner/compose.yaml"));
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
    public void testLdapProvisioner() throws Exception {
        HttpRequest testReq = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/system/ldap?_action=test"))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> testResp = httpClient.send(testReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, testResp.statusCode());

        JsonNode body = mapper.readTree(testResp.body());
        assertTrue(body.get("ok").asBoolean());
    }
}
