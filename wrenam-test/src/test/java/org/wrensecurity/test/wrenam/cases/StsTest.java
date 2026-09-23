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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMDefaults;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;
import tools.jackson.databind.JsonNode;

/**
 * REST STS (Security Token Service) system tests. Publishes a REST STS instance via the
 * <code>/sts-publish/rest</code> service and exercises the resulting token transformation
 * endpoint at <code>/rest-sts/{realm}/{deployment-url-element}</code>.
 *
 * <p>The transform under test is USERNAME → OPENIDCONNECT signed with HS256, chosen because it
 * exercises the publish/translate round-trip without requiring an additional signing keystore to
 * be staged into the AM container.
 */
@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
public class StsTest extends WrenAMTestBase {

    private static final String TEST_REALM = "/sts";

    private static final String DEPLOYMENT_URL_ELEMENT = "username-transformer";

    /**
     * Deployment subpath as catenated by {@code RestSTSInstanceConfig#getDeploymentSubPath}.
     */
    private static final String DEPLOYMENT_SUBPATH = "sts/" + DEPLOYMENT_URL_ELEMENT;

    private static final String OIDC_ISSUER = "wrenam-sts-test";

    private static final String OIDC_AUDIENCE = "wrenam-sts-audience";

    private static final String OIDC_CLIENT_SECRET = "topSecretClientSecret";

    @BeforeAll
    public void setupTestCase() throws Exception {
        setupTestConfig("sts");
    }

    /**
     * Publishes a REST STS instance via the JSON publish service. Asserts that the response
     * carries the expected <code>url_element</code> identifying the new instance.
     */
    @Test
    @Order(1)
    public void testPublishRestStsInstance() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();
        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        // Numeric/boolean values inside instance_state must be JSON strings — the publish handler
        // marshals state via a SMS Map<String,Set<String>> representation that goes through
        // String.valueOf, and the OIDC config's fromJson() then parses them back from strings.
        String publishResult = wrenamClient.newHttpRequest("sts-publish/rest?_action=create")
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody(
                        """
                        {
                            "invocation_context": "invocation_context_client_sdk",
                            "instance_state": {
                                "persist-issued-tokens-in-cts": "false",
                                "deployment-config": {
                                    "deployment-url-element": "%s",
                                    "deployment-realm": "%s",
                                    "deployment-auth-target-mappings": {
                                        "USERNAME": {
                                            "mapping-auth-index-type": "service",
                                            "mapping-auth-index-value": "ldapService"
                                        }
                                    },
                                    "deployment-tls-offload-engine-hosts": []
                                },
                                "supported-token-transforms": [
                                    {
                                        "inputTokenType": "USERNAME",
                                        "outputTokenType": "OPENIDCONNECT",
                                        "invalidateInterimOpenAMSession": true
                                    }
                                ],
                                "oidc-id-token-config": {
                                    "oidc-issuer": "%s",
                                    "oidc-audience": ["%s"],
                                    "oidc-signature-algorithm": "HS256",
                                    "oidc-token-lifetime-seconds": "600",
                                    "oidc-public-key-reference-type": "NONE",
                                    "oidc-client-secret": "%s",
                                    "oidc-claim-map": {}
                                }
                            }
                        }
                        """.formatted(DEPLOYMENT_URL_ELEMENT, TEST_REALM, OIDC_ISSUER, OIDC_AUDIENCE, OIDC_CLIENT_SECRET))
                .buildAndSend()
                .assertSuccess()
                .readStringBody();

        JsonNode publishJson = objectMapper.readTree(publishResult);
        assertEquals("success", publishJson.path("result").asString(""),
                "Unexpected publish result: " + publishResult);
        assertEquals(DEPLOYMENT_SUBPATH, publishJson.path("url_element").asString(""),
                "Unexpected deployment url_element: " + publishResult);
    }

    /**
     * Reads back the published instance via <code>GET /sts-publish/rest/{deployment-subpath}</code>.
     * Confirms the SMS persisted the configuration we just submitted.
     */
    @Test
    @Order(2)
    public void testReadPublishedInstance() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();
        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        JsonNode readJson = wrenamClient
                .newHttpRequest("sts-publish/rest/" + DEPLOYMENT_SUBPATH)
                .header("Accept", "application/json")
                .ssoHeader(adminToken)
                .buildAndSend()
                .assertSuccess()
                .readJsonBody();

        // Response keys the configuration by deployment subpath.
        JsonNode instance = readJson.get(DEPLOYMENT_SUBPATH);
        assertNotNull(instance, "Read response missing deployment subpath entry: " + readJson);
        assertEquals(DEPLOYMENT_URL_ELEMENT,
                instance.at("/deployment-config/deployment-url-element").asString(""),
                "Persisted deployment-url-element does not match");
        assertEquals(TEST_REALM,
                instance.at("/deployment-config/deployment-realm").asString(""),
                "Persisted deployment-realm does not match");
        assertEquals(OIDC_ISSUER,
                instance.at("/oidc-id-token-config/oidc-issuer").asString(""),
                "Persisted oidc-issuer does not match");
    }

    /**
     * Translates a USERNAME token into an OPENIDCONNECT id token via the published REST STS
     * instance. Verifies the issued token is a well-formed JWS and that the JWT payload carries
     * the configured issuer/audience and the expected subject.
     */
    @Test
    @Order(3)
    public void testTranslateUsernameToOpenIdConnect() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        // The translate action is excluded from SSO authentication by
        // RestSTSServiceHttpRouteProvider — credentials come from the request body.
        JsonNode translateResult = wrenamClient
                .newHttpRequest("rest-sts/" + DEPLOYMENT_SUBPATH + "?_action=translate")
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .postBody(
                        """
                        {
                            "input_token_state": {
                                "token_type": "USERNAME",
                                "username": "%s",
                                "password": "%s"
                            },
                            "output_token_state": {
                                "token_type": "OPENIDCONNECT",
                                "nonce": "wrenam-test-nonce",
                                "allow_access": true
                            }
                        }
                        """.formatted(TEST_USERNAME, TEST_PASSWORD))
                .buildAndSend()
                .assertSuccess()
                .readJsonBody();

        String issuedToken = translateResult.path("issued_token").asString("");
        assertNotNull(issuedToken, "issued_token missing from translate response: " + translateResult);
        assertTrue(!issuedToken.isEmpty(), "issued_token is empty");

        // A signed JWT (JWS Compact) has three base64url-encoded segments.
        String[] segments = issuedToken.split("\\.");
        assertEquals(3, segments.length, "Expected JWS Compact serialization with 3 segments, got: " + issuedToken);

        JsonNode payload = decodeJwtSegment(segments[1]);
        assertEquals(OIDC_ISSUER, payload.path("iss").asString(""),
                "Issued OIDC token has unexpected iss claim: " + payload);
        // The aud claim is serialised as a single JSON string when there is exactly one audience,
        // and as an array when there are multiple. Accept either shape.
        JsonNode aud = payload.path("aud");
        String audValue = aud.isArray() ? aud.at("/0").asString("") : aud.asString("");
        assertEquals(OIDC_AUDIENCE, audValue,
                "Issued OIDC token has unexpected aud claim: " + payload);
        assertEquals(TEST_USERNAME, payload.path("sub").asString(""),
                "Issued OIDC token has unexpected sub claim: " + payload);
        assertEquals("wrenam-test-nonce", payload.path("nonce").asString(""),
                "Issued OIDC token has unexpected nonce claim: " + payload);
    }

    /**
     * Bad credentials must fail the translate call rather than return a token. WrenAM currently
     * surfaces the AM authn rejection as 5xx through the STS layer rather than propagating the
     * underlying 401 — so check for any error response and confirm no token leaked back.
     */
    @Test
    @Order(4)
    public void testTranslateRejectsInvalidCredentials() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        WrenAMClient.HttpResponseWrapper response = wrenamClient
                .newHttpRequest("rest-sts/" + DEPLOYMENT_SUBPATH + "?_action=translate")
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .postBody(
                        """
                        {
                            "input_token_state": {
                                "token_type": "USERNAME",
                                "username": "%s",
                                "password": "definitely-not-the-right-password"
                            },
                            "output_token_state": {
                                "token_type": "OPENIDCONNECT",
                                "nonce": "wrenam-test-nonce",
                                "allow_access": true
                            }
                        }
                        """.formatted(TEST_USERNAME))
                .buildAndSend()
                .checkStatusCode(code -> assertTrue(code >= 400,
                        "Expected error response for bad credentials, got " + code));

        // Ensure no token was issued in the error path.
        JsonNode errorBody = response.readJsonBody();
        assertTrue(errorBody.path("issued_token").isMissingNode()
                || errorBody.path("issued_token").asString("").isEmpty(),
                "Bad credentials must not yield an issued_token: " + errorBody);
    }

    /**
     * Deletes the published instance and asserts the SMS read no longer returns it.
     */
    @Test
    @Order(5)
    public void testDeletePublishedInstance() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();
        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        wrenamClient.newHttpRequest("sts-publish/rest/" + DEPLOYMENT_SUBPATH)
                .header("Accept", "application/json")
                .ssoHeader(adminToken)
                .body("DELETE", "")
                .buildAndSend()
                .assertSuccess();

        wrenamClient.newHttpRequest("sts-publish/rest/" + DEPLOYMENT_SUBPATH)
                .header("Accept", "application/json")
                .ssoHeader(adminToken)
                .buildAndSend()
                .assertStatusCode(404);
    }

    private JsonNode decodeJwtSegment(String segment) {
        // Java's URL decoder accepts unpadded base64url, which is the format JWS uses.
        byte[] decoded = Base64.getUrlDecoder().decode(segment);
        return objectMapper.readTree(new String(decoded, StandardCharsets.UTF_8));
    }

}
