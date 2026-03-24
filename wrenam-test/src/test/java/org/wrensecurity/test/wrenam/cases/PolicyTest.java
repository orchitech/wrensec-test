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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wrensecurity.test.wrenam.base.WrenAMDefaults.USER_STORE_BASE_DN;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMClient.HttpResponseWrapper;
import org.wrensecurity.test.wrenam.base.WrenAMDefaults;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;
import tools.jackson.databind.JsonNode;

@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
public class PolicyTest extends WrenAMTestBase {

    private static final String TEST_REALM = "/policy";

    private static final String SUBJECT_USER_DN = "uid=john,ou=people," + USER_STORE_BASE_DN;

    @BeforeAll
    public void setupRealm() throws Exception {
        setupRealm(TEST_REALM.substring(1));
    }

    @Test
    @Order(1)
    public void testCreatePolicy() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        // Create URL resource type
        wrenamClient.newHttpRequest("json/resourcetypes?_action=create", TEST_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody(
                        """
                        {
                            "uuid": "UrlResourceType",
                            "name": "URL",
                            "actions": {
                                "DELETE": true,
                                "GET": true,
                                "HEAD": true,
                                "OPTIONS": true,
                                "PATCH": true,
                                "POST": true,
                                "PUT": true
                            },
                            "patterns": [
                                "*://*:*/*",
                                "*://*:*/*?*"
                            ]
                        }
                        """)
                .buildAndSend()
                .assertSuccess();

        // Create policy set
        wrenamClient.newHttpRequest("json/applications?_action=create", TEST_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody(
                        """
                        {
                            "name": "PolicyTestApplication",
                            "displayName": "PolicyTestApplication",
                            "resourceTypeUuids": [
                                "UrlResourceType"
                            ],
                            "realm": "/policy",
                            "applicationType": "iPlanetAMWebAgentService",
                            "conditions": [
                                "AMIdentityMembership",
                                "AND",
                                "AuthLevel",
                                "AuthenticateToRealm"
                            ],
                            "subjects": [
                                "AND",
                                "AuthenticatedUsers",
                                "Identity",
                                "NONE"
                            ],
                            "entitlementCombiner": "DenyOverride"
                        }
                        """)
                .buildAndSend()
                .assertSuccess();

        // Create first policy — allows POST, denies GET on create resource
        wrenamClient.newHttpRequest("json/policies?_action=create", TEST_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody(
                        """
                        {
                            "name": "Test policy",
                            "active": true,
                            "applicationName": "PolicyTestApplication",
                            "resourceTypeUuid": "UrlResourceType",
                            "actionValues": {
                                "POST": true,
                                "GET": false
                            },
                            "resources": [
                                "http://policy-test:8080/*?_action=create"
                            ],
                            "subject": {
                                "type": "AuthenticatedUsers"
                            },
                            "condition": {
                                "type": "AuthenticateToRealm",
                                "authenticateToRealm": "/policy"
                            },
                            "resourceAttributes": [
                                {
                                    "type": "User",
                                    "propertyName": "dn",
                                    "propertyValues": []
                                },
                                {
                                    "type": "Static",
                                    "propertyName": "foo",
                                    "propertyValues": [
                                        "bar"
                                    ]
                                }
                            ]
                        }
                        """)
                .buildAndSend()
                .assertSuccess();

        // Create second policy 2 — denies HEAD on edit resource (from a different realm)
        wrenamClient.newHttpRequest("json/policies?_action=create", TEST_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody(
                        """
                        {
                            "name": "Test policy 2",
                            "active": true,
                            "applicationName": "PolicyTestApplication",
                            "resourceTypeUuid": "UrlResourceType",
                            "actionValues": {
                                "HEAD": false
                            },
                            "resources": [
                                "http://policy-test:8080/*?_action=edit"
                            ],
                            "subject": {
                                "type": "AuthenticatedUsers"
                            },
                            "condition": {
                                "type": "AuthenticateToRealm",
                                "authenticateToRealm": "/different-realm"
                            },
                            "resourceAttributes": [
                                {
                                    "type": "User",
                                    "propertyName": "cn",
                                    "propertyValues": []
                                }
                            ]
                        }
                        """)
                .buildAndSend()
                .assertSuccess();
    }

    @Test
    @Order(2)
    public void testEvaluatePolicy() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        String userToken = wrenamClient.authenticate(TEST_REALM)
                .immediateAuth("john", "password")
                .getSsoTokenId();

        // Evaluate policies for both resources
        JsonNode evalBody = objectMapper.readTree(
                """
                {
                    "subject": {
                        "ssoToken": "{{SSO_TOKEN}}"
                    },
                    "resources": [
                        "http://policy-test:8080/first?_action=create",
                        "http://policy-test:8080/second?_action=edit"
                    ],
                    "application": "PolicyTestApplication"
                }
                """);
        evalBody.at("/subject").asObject().put("ssoToken", userToken);

        HttpResponseWrapper evalResponse = wrenamClient
                .newHttpRequest("json/policies?_action=evaluate", TEST_REALM)
                .header("Accept", "application/json")
                .ssoHeader(adminToken)
                .postBody(evalBody)
                .buildAndSend()
                .assertSuccess();

        JsonNode results = evalResponse.readJsonBody();
        assertEquals(2, results.size(), "Expected 2 policy evaluation results");

        // Verify first policy result
        JsonNode firstPolicyResult = results.valueStream()
                .filter(value -> value.get("resource").asString().contains("first"))
                .findFirst().orElseThrow();
        assertTrue(firstPolicyResult.at("/actions/POST").asBoolean(), "First policy should allow POST");
        assertFalse(firstPolicyResult.at("/actions/GET").asBoolean(), "First policy should deny GET");
        assertEquals("bar", firstPolicyResult.at("/attributes/foo/0").asString(),
                "First policy should return static attribute foo=bar");
        assertEquals(SUBJECT_USER_DN, firstPolicyResult.at("/attributes/dn/0").asString(),
                "First policy should return subject DN");

        // Verify second result — no actions apply (wrong realm condition)
        JsonNode secondPolicyResult = results.valueStream()
                .filter(value -> value.get("resource").asString().contains("second"))
                .findFirst().orElseThrow();
        assertTrue(secondPolicyResult.get("actions").isEmpty(), "Second policy should have no actions");
        assertNotNull(secondPolicyResult.at("/advices/AuthenticateToRealmConditionAdvice"),
                "Second policy should have AuthenticateToRealm advice");
    }

}
