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

import java.io.File;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.testcontainers.containers.ComposeContainer;
import org.wrensecurity.wrenig.test.base.BaseWrenigTest;
import org.wrensecurity.wrenig.test.base.TomcatStartupWaitStrategy;

@TestInstance(Lifecycle.PER_CLASS)
public class ScriptingTest extends BaseWrenigTest {

    @SuppressWarnings("resource")
    @BeforeAll
    public void init() {
        environment = new ComposeContainer(new File("src/test/resources/cases/scripting/compose.yaml")).withLocalCompose(true);
        environment.waitingFor(WRENIG_CONTAINER_NAME, new TomcatStartupWaitStrategy());
        environment.start();
    }

    @AfterAll
    public void teardown() {
        if (environment != null) {
            environment.stop();
        }
    }

    @Test
    public void testInlineGroovy() throws Exception {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create("http://wrenig.wrensecurity.local:8080/inline")).build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertEquals("Hello from inline Groovy", response.body());
    }

    @Test
    public void testGroovyFile() throws Exception {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create("http://wrenig.wrensecurity.local:8080/file")).build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertEquals("Hello from Groovy file", response.body());
    }

}
