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
 * Copyright 2025 Wren Security.
 */
package org.wrensecurity.wrenig.test.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.Response;
import java.io.File;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.testcontainers.containers.ComposeContainer;
import org.wrensecurity.wrenig.test.base.BaseWrenigTest;
import org.wrensecurity.wrenig.test.base.TomcatStartupWaitStrategy;

@TestInstance(Lifecycle.PER_CLASS)
public class AuthSaml2Test extends BaseWrenigTest {

    private static final String WRENIG_AUTH_ENDPOINT = "http://wrenig.wrensecurity.local:8080/auth";

    private static final String TEST_USER_USERNAME = "demo";

    private static final String TEST_USER_PASSWORD = "changeit";

    private final ObjectMapper mapper = new ObjectMapper();

    @SuppressWarnings("resource")
    @BeforeAll
    public void init() throws Exception {
        environment = new ComposeContainer(new File("src/test/resources/cases/auth-saml/compose.yaml")).withLocalCompose(true);
        environment.waitingFor(WRENIG_CONTAINER_NAME, new TomcatStartupWaitStrategy());
        environment.waitingFor("wrenam", new TomcatStartupWaitStrategy());
        environment.start();
    }

    @AfterAll
    public void teardown() {
        if (environment != null) {
            environment.stop();
        }
    }


    @Test
    public void testAuth() throws Exception {
        try (Playwright playwright = Playwright.create()) {
            Browser browser = playwright.chromium().launch();
            Page page = browser.newPage();
            page.navigate(WRENIG_AUTH_ENDPOINT);
            Response response = page.waitForResponse(WRENIG_AUTH_ENDPOINT, () -> {
                page.locator("id=idToken1").fill(TEST_USER_USERNAME);
                page.locator("id=idToken2").fill(TEST_USER_PASSWORD);
                page.locator("id=loginButton_0").click();
            });
            assertTrue(response.ok());
            Map<String, String> responseBody = mapper.readValue(response.body(),
                    new TypeReference<Map<String, String>>() {});
            assertEquals("wrenig-session", responseBody.get("session"));
            assertEquals(TEST_USER_USERNAME, responseBody.get("username"));
            browser.close();
        }
    }

}
