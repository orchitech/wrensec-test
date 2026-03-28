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
import static org.wrensecurity.test.base.support.CustomAssertions.assertSuccess;

import java.net.URI;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.FormElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.ContainerState;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.base.support.UrlQueryBuilder;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMClient.HttpResponseWrapper;
import org.wrensecurity.test.wrenam.base.WrenAMContainer;
import org.wrensecurity.test.wrenam.base.WrenAMTestBase;

/**
 * System tests for Wren:AM's federation features.
 *
 * <p>
 * A dedicated {@code remote} Wren:AM container acts as the external SAML provider. The main
 * Wren:AM test cluster acts as the hosted SAML provider. For additional details go check
 * <code>cases/federation</code> test resources.
 */
@Testcontainers
@TestInstance(Lifecycle.PER_CLASS)
public class FederationTest extends WrenAMTestBase {

    private static final String TEST_REALM = "/federation";

    private static final String LOCAL_IDP_META_ALIAS = "/federation/local-idp";

    private static final String LOCAL_SP_META_ALIAS = "/federation/local-sp";

    private static final String REMOTE_IDP_ENTITY_ID = "https://wrenam.wrensecurity.remote/auth/saml/test-idp";

    private static final String REMOTE_SP_ENTITY_ID = "https://wrenam.wrensecurity.remote/auth/saml/test-sp";

    @Container
    @SuppressWarnings("resource")
    private static final WrenAMContainer remote = new WrenAMContainer()
            .withNetwork(network)
            .withNetworkAliases("wrenam.wrensecurity.remote")
            .withEnv("WRENAM_SERVER_URL", "http://wrenam.wrensecurity.remote:8080")
            .withInitConfig("/wrenam/init/init-remote.properties");

    @BeforeAll
    public void setupLocalConfig() throws Exception {
        copySetupData(wrenam1, "federation");
        importKeystore(wrenam1);
        copySetupData(wrenam2, "federation");
        importKeystore(wrenam2);
        execBatchConfig(wrenam1, "federation/local/config.batch");
    }

    @BeforeAll
    protected void setupRemoteConfig() throws Exception {
        copySetupData(remote, "federation");
        importKeystore(remote);
        execBatchConfig(remote, "federation/remote/config.batch");
    }

    private void importKeystore(ContainerState container) throws Exception {
        ExecResult result = container.execInContainer(
                "keytool", "-importkeystore",
                "-srckeystore", "/srv/wrenam/setup/federation/keystore.p12",
                "-srcstoretype", "PKCS12",
                "-srcstorepass", "changeit",
                "-destkeystore", "/srv/wrenam/auth/keystore.jceks",
                "-deststoretype", "JCEKS",
                "-deststorepass:file", "/srv/wrenam/auth/.storepass");
        assertSuccess(result, "Unable to import keystore");
    }

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
                .postBody(redirectQuery.toString())
                .buildAndSend();

        // SP establishes the federation session and redirects to the relay state
        assertEquals(302, acsResponse.unwrap().statusCode(),
                "SP ACS should redirect on successful assertion processing");
        assertEquals("http://wrenam.wrensecurity.local:8080/auth/",
                acsResponse.unwrap().headers().firstValue("Location"),
                "SP ACS should redirect to a default RelayState");
    }

}
