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
package org.wrensecurity.wrenidm.test.base;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

public abstract class BaseWrenidmTest {

    // Default Wren:IDM Docker container name
    protected static final String WRENIDM_CONTAINER_NAME = "wrenidm";

    protected static final String WRENIDM_BASE_URL = "http://wrenidm.wrensecurity.local:8080";

    protected static final String ANONYMOUS_AUTHORIZATION_HEADER_VALUE = "Basic " + Base64.getEncoder()
            .encodeToString("anonymous:anonymous".getBytes());

    protected static final String ADMIN_AUTHORIZATION_HEADER_VALUE = "Basic " + Base64.getEncoder()
            .encodeToString("openidm-admin:openidm-admin".getBytes());

    protected static final ObjectMapper mapper = new ObjectMapper();

    protected final HttpClient httpClient = HttpClient.newHttpClient();

    protected ComposeContainer environment;

    protected static final HttpWaitStrategy WRENIDM_STARTUP_WAIT_STRATEGY = Wait
            .forHttp("/openidm/info/ping")
            .withHeader("Authorization", ANONYMOUS_AUTHORIZATION_HEADER_VALUE)
            .forStatusCode(200)
            .forResponsePredicate(response -> {
                Map<String, String> responseBody = mapper.readValue(response,
                        new TypeReference<Map<String, String>>() {});
                return "ACTIVE_READY".equals(responseBody.get("state"));
            })
            .withReadTimeout(Duration.ofMinutes(5));

}
