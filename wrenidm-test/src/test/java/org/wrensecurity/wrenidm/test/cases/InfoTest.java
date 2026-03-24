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
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.testcontainers.containers.ComposeContainer;
import org.wrensecurity.wrenidm.test.base.BaseWrenidmTest;
import tools.jackson.core.type.TypeReference;

@TestInstance(Lifecycle.PER_CLASS)
public class InfoTest extends BaseWrenidmTest {

    @BeforeAll
    public void init() {
        environment = new ComposeContainer(new File("src/test/resources/cases/info/compose.yaml"));
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
    public void testPing() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/info/ping"))
                .header("Authorization", ANONYMOUS_AUTHORIZATION_HEADER_VALUE)
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        Map<String, String> responseBody = mapper.readValue(response.body(),
                new TypeReference<Map<String, String>>() {});
        assertEquals("ACTIVE_READY", responseBody.get("state"));
    }

    @Test
    public void testGetVersion() throws Exception {
        String versionRegex = "^[\\d]+.[\\d]+.[\\d]+(-[A-Z][A-Z0-9-]*)?$";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/info/version"))
                .header("Authorization", ANONYMOUS_AUTHORIZATION_HEADER_VALUE)
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        Map<String, String> responseBody = mapper.readValue(response.body(),
                new TypeReference<Map<String, String>>() {});
        assertTrue(Pattern.matches(versionRegex, responseBody.get("productVersion")));
    }

}
