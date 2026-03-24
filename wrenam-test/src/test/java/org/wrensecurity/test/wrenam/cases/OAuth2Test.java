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
 * Copyright 2026 Wren Security
 */

package org.wrensecurity.test.wrenam.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMClient.HttpResponseWrapper;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;
import tools.jackson.databind.JsonNode;

@TestInstance(Lifecycle.PER_CLASS)
public class OAuth2Test extends WrenAMTestBase {

    private static final String TEST_REALM = "/oauth2";

    private static final String TEST_USERNAME = "john";

    private static final String TEST_PASSWORD = "password";

    private static final String AGENT_ID = "test";

    private static final String AGENT_SECRET = "password";

    private static final String REDIRECT_URI = "http://test.example.org";

    @BeforeAll
    public void setupRealm() throws Exception {
        super.setupRealm(TEST_REALM.substring(1));
    }

    @Test
    public void testOidcAuthorizationCodeFlow() throws Exception {
        WrenAMClient userClient = getWrenAMClient();

        // Step 1: authenticate as end-user and obtain session token
        userClient.authenticate(TEST_REALM)
                .immediateAuth(TEST_USERNAME, TEST_PASSWORD)
                .useAsSession();

        // Step 2: request authorization code
        String authorizeQuery = "response_type=code"
                + "&client_id=" + AGENT_ID
                + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=openid%20profile"
                + "&state=foobar"
                + "&realm=" + URLEncoder.encode(TEST_REALM, StandardCharsets.UTF_8);
        HttpResponseWrapper authorizeResponse = userClient
                .newHttpRequest("oauth2/authorize?" + authorizeQuery)
                .buildAndSend()
                .assertStatusCode(302);

        Optional<String> redirectLocation = authorizeResponse.unwrap().headers().firstValue("Location");
        assertTrue(redirectLocation.isPresent(), "No Location header in authorization response");

        Matcher codeMatcher = Pattern.compile("[?&]code=([^&]+)").matcher(redirectLocation.get());
        assertTrue(codeMatcher.find(), "Authorization code not found in redirect URL");
        String authorizationCode = codeMatcher.group(1);

        WrenAMClient agentClient = getWrenAMClient();

        // Step 3: exchange authorization code for tokens
        String exchangeBody = "grant_type=authorization_code"
                + "&code=" + authorizationCode
                + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8);
        JsonNode exchangeResult = agentClient
                .newHttpRequest("oauth2/access_token", TEST_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .basicAuth(AGENT_ID, AGENT_SECRET)
                .postBody(exchangeBody)
                .buildAndSend()
                .assertSuccess()
                .readJsonBody();

        assertTrue(exchangeResult.has("access_token"), "Missing access_token");
        assertTrue(exchangeResult.has("refresh_token"), "Missing refresh_token");
        assertTrue(exchangeResult.has("id_token"), "Missing id_token");

        // Step 4: introspect the access token
        JsonNode introspectResult = agentClient
                .newHttpRequest("oauth2/tokeninfo", TEST_REALM)
                .header("Authorization", "Bearer " + exchangeResult.get("access_token").asString())
                .buildAndSend()
                .assertSuccess()
                .readJsonBody();

        assertNotNull(introspectResult.get("expires_in"), "Missing expires_in field");
        assertEquals(TEST_REALM, introspectResult.get("realm").asString(), "Token realm should match");
    }

}
