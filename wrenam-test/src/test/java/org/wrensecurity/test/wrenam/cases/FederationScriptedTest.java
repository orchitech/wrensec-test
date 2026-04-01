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

import java.net.URI;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.FormElement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.wrensecurity.test.base.support.UrlQueryBuilder;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMClient.HttpResponseWrapper;

@TestInstance(Lifecycle.PER_CLASS)
public class FederationScriptedTest extends FederationTestBase {

    @Test
    public void testSpInitiatedSso() throws Exception {
        WrenAMClient spClient = getWrenAMClient();
        WrenAMClient idpClient = remote.getWrenAMClient();

        // Step 1: Authenticate at the remote IdP to establish an IdP-side session
        idpClient.authenticate("/federation")
                .immediateAuth(TEST_USERNAME, TEST_PASSWORD)
                .useAsSession();

        // Step 2: Initiate SP-initiated SSO — SP builds AuthnRequest and redirects to IdP
        String ssoInitQuery = new UrlQueryBuilder()
                .param("metaAlias", LOCAL_SP_META_ALIAS)
                .param("idpEntityID", REMOTE_IDP_ENTITY_ID)
                .build();
        HttpResponseWrapper ssoInitResponse = spClient
                .newHttpRequest("spssoinit?" + ssoInitQuery)
                .buildAndSend()
                .assertStatusCode(302);

        URI idpRedirectUrl = ssoInitResponse.unwrap().headers()
                .firstValue("Location")
                .map(URI::create)
                .orElseThrow(() -> new AssertionError("Missing Location header in SP SSO init response"));
        assertEquals("wrenam.wrensecurity.remote", idpRedirectUrl.getHost());

        // Step 3: Follow redirect to remote IdP — IdP finds existing session, returns SAML Response form
        HttpResponseWrapper idpResponse = idpClient
                .newHttpRequest(idpRedirectUrl)
                .buildAndSend();

        Document responseHtml = Jsoup.parse(idpResponse.readStringBody());
        FormElement responseForm = (FormElement) responseHtml.selectFirst("form");
        assertNotNull(responseForm, "Missing response FORM element");

        // Rebuild redirect target and data from the HTML form
        UrlQueryBuilder redirectQuery = new UrlQueryBuilder();
        responseForm.formData().stream()
                .forEach(field -> redirectQuery.param(field.key(), field.value()));
        String redirectUrl = responseForm.attr("action");

        // Step 4: POST SAMLResponse to the SP's Assertion Consumer Service
        HttpResponseWrapper acsResponse = spClient
                .newHttpRequest(redirectUrl)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .postBody(redirectQuery.build())
                .buildAndSend();

        // SP establishes the federation session and redirects to the relay state
        assertEquals(302, acsResponse.unwrap().statusCode(),
                "SP ACS should redirect on successful assertion processing");
        assertEquals("http://wrenam.wrensecurity.test:8080/auth/?realm=%2Ffederation",
                acsResponse.unwrap().headers().firstValue("Location").get(),
                "SP ACS should redirect to a default RelayState");
    }

}
