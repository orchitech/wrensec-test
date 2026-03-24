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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.ComposeContainer;
import org.wrensecurity.wrenidm.test.base.BaseWrenidmTest;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EmailTest extends BaseWrenidmTest {

    private static final String SMTP_API_BASE_URL = "http://smtp.wrensecurity.local:8025";

    private static final String EMAIL_DATA = """
        {
          "type": "text/html",
          "from": "idm@wrensecurity.org",
          "to": "foobar@wrensecurity.org",
          "subject": "Test subject",
          "body": "Test body"
        }
        """;

    @BeforeAll
    public void init() {
        environment = new ComposeContainer(new File("src/test/resources/cases/email/compose.yaml"));
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
    public void testSendEmailAndCheckInbox() throws Exception {
        // Send email via Wren:IDM
        HttpRequest sendReq = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/external/email?_action=send"))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(EMAIL_DATA))
                .build();
        HttpResponse<String> sendResp = httpClient.send(sendReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, sendResp.statusCode());
        Map<String, Object> sendBody = mapper.readValue(sendResp.body(),
                new TypeReference<Map<String, Object>>() {});
        assertEquals("OK", sendBody.get("status"));

        // Check SMTP inbox (MailHog API)
        HttpRequest inboxReq = HttpRequest.newBuilder()
                .uri(URI.create(SMTP_API_BASE_URL + "/api/v2/messages"))
                .build();
        HttpResponse<String> inboxResp = httpClient.send(inboxReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, inboxResp.statusCode());
        JsonNode inbox = mapper.readTree(inboxResp.body());
        assertEquals(1, inbox.get("total").asInt());

        JsonNode message = inbox.get("items").get(0);
        JsonNode headers = message.get("Content").get("Headers");
        assertTrue(headers.get("Content-Type").get(0).asString().contains("text/html"));
        assertEquals("idm@wrensecurity.org", headers.get("From").get(0).asString());
        assertEquals("foobar@wrensecurity.org", headers.get("To").get(0).asString());
        assertEquals("Test subject", headers.get("Subject").get(0).asString());
        assertEquals("Test body", message.get("Content").get("Body").asString());
    }
}
