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

import static com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat;

import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.junit.UsePlaywright;
import com.microsoft.playwright.options.Cookie;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.wrensecurity.test.base.support.UrlQueryBuilder;
import org.wrensecurity.test.wrenam.base.PlaywrightOptions;
import org.wrensecurity.test.wrenam.base.WrenAMClient;
import org.wrensecurity.test.wrenam.base.WrenAMDefaults;

@UsePlaywright(PlaywrightOptions.class)
@TestInstance(Lifecycle.PER_CLASS)
public class FederationBrowserTest extends FederationTestBase {

    @Test
    public void testSpInitiatedSsoWithBrowser(BrowserContext context, Page page) throws Exception {
        WrenAMClient idpClient = remote.getWrenAMClient();

        // Step 1: Authenticate at the remote IdP to establish an IdP-side session
        String idpTokenId = idpClient.authenticate("/federation")
                .immediateAuth(TEST_USERNAME, TEST_PASSWORD)
                .getSsoTokenId();

        // Pre-seed the IdP session cookie so the browser carries it when redirected to the IdP
        context.addCookies(Arrays.asList(new Cookie(WrenAMDefaults.SSO_SESSION_HEADER, idpTokenId)
                .setDomain(".wrensecurity.remote")
                .setPath("/")));

        // Step 3: Navigate browser to SP SSO init (SP -> IdP -> ACS -> profile)
        String ssoInitQuery = new UrlQueryBuilder()
                .param("metaAlias", LOCAL_SP_META_ALIAS)
                .param("idpEntityID", REMOTE_IDP_ENTITY_ID)
                .build();
        page.navigate("http://wrenam.wrensecurity.test:8080/auth/spssoinit?" + ssoInitQuery);

        // Step 4: Wait for the profile page to be displayed
        page.waitForURL(url -> url.startsWith("http://wrenam.wrensecurity.test:8080/auth/XUI/"));
        assertThat(page.locator("#input-mail")).hasValue("john.doe@example.org");
    }

}
