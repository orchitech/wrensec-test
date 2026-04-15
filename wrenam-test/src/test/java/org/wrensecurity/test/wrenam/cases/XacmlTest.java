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

import java.util.Map;
import javax.xml.transform.Source;
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
import org.xmlunit.builder.Input;
import org.xmlunit.xpath.JAXPXPathEngine;
import tools.jackson.databind.JsonNode;

@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
public class XacmlTest extends WrenAMTestBase {

    private static final String SOURCE_REALM = "/xacml";

    private static final String TARGET_REALM = "/xacml-target";

    private static final String SUBJECT_USER_DN = "uid=john,ou=people," + USER_STORE_BASE_DN;

    private static final String XACML_MEDIA_TYPE = "application/xacml+xml; version=3.0";

    private static final String XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";

    private static final String POLICY_NAME_1 = "Test policy";

    private static final String POLICY_NAME_2 = "Test policy 2";

    private byte[] exportedXacml;

    @BeforeAll
    public void setupTestCase() throws Exception {
        setupTestConfig("xacml");
    }

    /**
     * Arrange step — populate the source realm with a resource type, an application and two
     * policies via the JSON CREST API. Kept separate from the XACML-specific steps so a failure
     * here signals a setup problem, not a JAXB regression.
     */
    @Test
    @Order(1)
    public void testSetupPolicies() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();
        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        // Create URL resource type
        wrenamClient.newHttpRequest("json/resourcetypes?_action=create", SOURCE_REALM)
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

        // Create policy set (application)
        wrenamClient.newHttpRequest("json/applications?_action=create", SOURCE_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody(
                        """
                        {
                            "name": "XacmlTestApplication",
                            "displayName": "XacmlTestApplication",
                            "resourceTypeUuids": [
                                "UrlResourceType"
                            ],
                            "realm": "/xacml",
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

        // Create first policy — allows POST, denies GET on the create resource. No condition is
        // set because conditions like AuthenticateToRealm are realm-literal and would change the
        // policy's effective behaviour once imported into a different realm, muddying the
        // round-trip check. The second policy below still exercises the Condition JAXB surface.
        wrenamClient.newHttpRequest("json/policies?_action=create", SOURCE_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody(
                        """
                        {
                            "name": "Test policy",
                            "active": true,
                            "applicationName": "XacmlTestApplication",
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

        // Create second policy — denies HEAD on the edit resource, gated on a realm the user is
        // not authenticated to, so evaluation should return an AuthenticateToRealmConditionAdvice
        wrenamClient.newHttpRequest("json/policies?_action=create", SOURCE_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .ssoHeader(adminToken)
                .postBody(
                        """
                        {
                            "name": "Test policy 2",
                            "active": true,
                            "applicationName": "XacmlTestApplication",
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

    /**
     * Baseline — evaluate the freshly created policies in the source realm. Establishes that the
     * policy set behaves as expected before any XACML round-trip, so a later failure on the target
     * realm points unambiguously at the export/import path rather than at the source fixture.
     */
    @Test
    @Order(2)
    public void testSourcePoliciesEvaluate() throws Exception {
        assertPoliciesEvaluateCorrectly(SOURCE_REALM);
    }

    /**
     * Export the source realm's policies as XACML 3.0 XML and assert the shape of the marshalled
     * document. Captures the body for the subsequent import step.
     */
    @Test
    @Order(3)
    public void testExportXacml() throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();
        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        HttpResponseWrapper exportResponse = wrenamClient
                .newHttpRequest("xacml/policies", SOURCE_REALM)
                .header("Accept", XACML_MEDIA_TYPE)
                .ssoHeader(adminToken)
                .buildAndSend()
                .assertSuccess();

        String contentType = exportResponse.unwrap().headers().firstValue("Content-Type").orElse("");
        assertTrue(contentType.startsWith("application/xacml+xml"),
                "Unexpected export content type: " + contentType);

        exportedXacml = exportResponse.unwrap().body();

        Source xml = Input.fromByteArray(exportedXacml).build();
        JAXPXPathEngine xpath = new JAXPXPathEngine();
        xpath.setNamespaceContext(Map.of("x", XACML_NS));

        assertEquals("PolicySet", xpath.evaluate("local-name(/*)", xml),
                "Expected a XACML PolicySet root element");
        assertEquals(XACML_NS, xpath.evaluate("namespace-uri(/*)", xml),
                "Unexpected root namespace");
        assertEquals("2", xpath.evaluate("count(//x:Policy)", xml),
                "Expected two exported policies");
        assertEquals("true", xpath.evaluate(
                "boolean(//x:Policy[contains(@PolicyId,'" + POLICY_NAME_1 + "')])", xml),
                "Exported XACML is missing '" + POLICY_NAME_1 + "'");
        assertEquals("true", xpath.evaluate(
                "boolean(//x:Policy[contains(@PolicyId,'" + POLICY_NAME_2 + "')])", xml),
                "Exported XACML is missing '" + POLICY_NAME_2 + "'");
    }

    /**
     * Import the captured XACML body into a clean target realm. Asserts the import response
     * references the expected policies — this covers the unmarshalling path.
     */
    @Test
    @Order(4)
    public void testImportXacmlIntoFreshRealm() throws Exception {
        assertNotNull(exportedXacml, "Export step must run before import");

        WrenAMClient wrenamClient = getWrenAMClient();
        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        JsonNode importResult = wrenamClient
                .newHttpRequest("xacml/policies", TARGET_REALM)
                .header("Accept", "application/json")
                .header("Content-Type", XACML_MEDIA_TYPE)
                .ssoHeader(adminToken)
                .postBody(new String(exportedXacml, java.nio.charset.StandardCharsets.UTF_8))
                .buildAndSend()
                .assertSuccess()
                .readJsonBody();

        assertTrue(importResult.isArray(), "Expected import response to be a JSON array");

        boolean firstImported = false;
        boolean secondImported = false;
        for (JsonNode step : importResult) {
            String name = step.path("name").asString("");
            if (name.equals(POLICY_NAME_1)) {
                firstImported = true;
            } else if (name.equals(POLICY_NAME_2)) {
                secondImported = true;
            }
        }
        assertTrue(firstImported, "Import response is missing '" + POLICY_NAME_1 + "'");
        assertTrue(secondImported, "Import response is missing '" + POLICY_NAME_2 + "'");
    }

    /**
     * Evaluate the reimported policies in the target realm and assert the same behaviour as the
     * source realm. A structural XML comparison would miss silent JAXB data loss (dropped fields,
     * reordered attributes) — re-evaluation catches it by treating the round-trip as a behavioural
     * equivalence check.
     */
    @Test
    @Order(5)
    public void testReimportedPoliciesEvaluate() throws Exception {
        assertPoliciesEvaluateCorrectly(TARGET_REALM);
    }

    /**
     * Evaluate the two policies in the given realm and assert they behave as configured. Shared
     * by the source-realm baseline and the target-realm round-trip check so both sides are held
     * to exactly the same expectations.
     */
    private void assertPoliciesEvaluateCorrectly(String realm) throws Exception {
        WrenAMClient wrenamClient = getWrenAMClient();

        String adminToken = wrenamClient.authenticate()
                .immediateAuth(WrenAMDefaults.ADMIN_USERNAME, WrenAMDefaults.ADMIN_PASSWORD)
                .getSsoTokenId();

        String userToken = wrenamClient.authenticate(realm)
                .immediateAuth(TEST_USERNAME, TEST_PASSWORD)
                .getSsoTokenId();

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
                    "application": "XacmlTestApplication"
                }
                """);
        evalBody.at("/subject").asObject().put("ssoToken", userToken);

        HttpResponseWrapper evalResponse = wrenamClient
                .newHttpRequest("json/policies?_action=evaluate", realm)
                .header("Accept", "application/json")
                .ssoHeader(adminToken)
                .postBody(evalBody)
                .buildAndSend()
                .assertSuccess();

        JsonNode results = evalResponse.readJsonBody();
        assertEquals(2, results.size(), "Expected 2 policy evaluation results in " + realm);

        JsonNode firstPolicyResult = results.valueStream()
                .filter(value -> value.get("resource").asString().contains("first"))
                .findFirst().orElseThrow();
        assertTrue(firstPolicyResult.at("/actions/POST").asBoolean(),
                "First policy should allow POST in " + realm);
        assertFalse(firstPolicyResult.at("/actions/GET").asBoolean(),
                "First policy should deny GET in " + realm);
        assertEquals("bar", firstPolicyResult.at("/attributes/foo/0").asString(),
                "First policy should return static attribute foo=bar in " + realm);
        assertEquals(SUBJECT_USER_DN, firstPolicyResult.at("/attributes/dn/0").asString(),
                "First policy should return subject DN in " + realm);

        JsonNode secondPolicyResult = results.valueStream()
                .filter(value -> value.get("resource").asString().contains("second"))
                .findFirst().orElseThrow();
        assertTrue(secondPolicyResult.get("actions").isEmpty(),
                "Second policy should have no actions in " + realm);
        assertNotNull(secondPolicyResult.at("/advices/AuthenticateToRealmConditionAdvice"),
                "Second policy should carry AuthenticateToRealm advice in " + realm);
    }

}
