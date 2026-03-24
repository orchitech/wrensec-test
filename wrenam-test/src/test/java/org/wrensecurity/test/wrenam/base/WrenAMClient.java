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

package org.wrensecurity.test.wrenam.base;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.testcontainers.containers.ContainerState;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.NullNode;

/**
 * Wren:AM HTTP client wrapper capable of switching site / server name for the container host
 * and handing the original host in the <code>Host</code> HTTP header.
 */
public class WrenAMClient {

    static {
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "Host");
    }

    private final CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);

    private final HttpClient httpClient = HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .build();

    private final URI originalBaseUri;

    private final URI switchedBaseUri;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Create a new Wren:AM client that targets the given container using the given base URI.
     */
    public WrenAMClient(ContainerState container, URI baseUri) {
        originalBaseUri = baseUri;
        try {
            this.switchedBaseUri = new URI(baseUri.getScheme(), baseUri.getUserInfo(),
                    container.getHost(), container.getMappedPort(baseUri.getPort()),
                    baseUri.getPath() + "/", baseUri.getQuery(), baseUri.getFragment());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid base URI", e);
        }
    }

    /**
     * Create a new HTTP request for the given relative URI.
     */
    public HttpRequestBuilder newHttpRequest(String uri) {
        return newHttpRequest(URI.create(uri));
    }

    /**
     * Create a new HTTP request for the given relative URI and the given realm.
     */
    public HttpRequestBuilder newHttpRequest(String uri, String realm) {
        return newHttpRequest(buildRealmUri(uri, realm));
    }

    /**
     * Create a new Wren:AM HTTP request for the given relative URI.
     */
    public HttpRequestBuilder newHttpRequest(URI uri) {
        return new HttpRequestBuilder(uri);
    }

    /**
     * Start authentication process for the ROOT realm.
     */
    public AuthenticationHandler authenticate() {
        return authenticate("/");
    }

    /**
     * Start authentication for the given realm.
     */
    public AuthenticationHandler authenticate(String realm) {
        return new AuthenticationHandler(buildRealmUri("json/authenticate", realm));
    }

    /**
     * Use the given token ID as a SSO session cookie.
     */
    public WrenAMClient useSsoSession(String tokenId) {
        HttpCookie sessionCookie = new HttpCookie(WrenAMDefaults.SSO_SESSION_HEADER, tokenId);
        sessionCookie.setPath("/");
        cookieManager.getCookieStore().add(switchedBaseUri, sessionCookie);
        return this;
    }

    /**
     * Remove all SSO session cookies.
     */
    public WrenAMClient clearSsoSession() {
        for (HttpCookie cookie : cookieManager.getCookieStore().get(switchedBaseUri)) {
            if (cookie.getName().equals(WrenAMDefaults.SSO_SESSION_HEADER)) {
                cookieManager.getCookieStore().remove(switchedBaseUri, cookie);
            }
        }
        return this;
    }

    /**
     * Logout SSO session referenced by the session cookie from the ROOT realm.
     */
    public HttpResponseWrapper logoutSession() throws InterruptedException, IOException {
        return logoutSession("/");
    }

    /**
     * Logout SSO session referenced by the session cookie from the given realm.
     */
    public HttpResponseWrapper logoutSession(String realm) throws InterruptedException, IOException {
        return newHttpRequest(buildRealmUri("json/sessions?_action=logout", realm))
                .postBody(objectMapper.createObjectNode())
                .buildAndSend();
    }

    /**
     * Perform SSO session logout from the ROOT realm.
     */
    public HttpResponseWrapper logoutToken(String tokenId) throws InterruptedException, IOException {
        return logoutToken(tokenId, "/");
    }

    /**
     * Perform SSO session logout from the given realm.
     */
    public HttpResponseWrapper logoutToken(String tokenId, String realm) throws InterruptedException, IOException {
        return newHttpRequest(buildRealmUri("json/sessions?_action=logout", realm))
                .ssoHeader(tokenId)
                .postBody(objectMapper.createObjectNode())
                .buildAndSend();
    }

    /**
     * Send request and read the response as string entity.
     */
    public HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
        return httpClient.send(request, BodyHandlers.ofString());
    }

    /**
     * Build realm specific URI by adding <code>realm</code> query parameter.
     */
    private URI buildRealmUri(String uri, String realm) {
        return URI.create(uri + (uri.contains("?") ? "&" : "?") + "realm="
                + URLEncoder.encode(realm, StandardCharsets.UTF_8));
    }

    /**
     * HTTP request builder.
     */
    public class HttpRequestBuilder {

        private HttpRequest.Builder request;

        private HttpRequestBuilder(URI uri) {
            this.request = HttpRequest.newBuilder()
                    .uri(switchedBaseUri.resolve(uri))
                    .header("Host", originalBaseUri.getHost());
        }

        /**
         * Get the raw HTTP request builder.
         */
        public HttpRequest.Builder unwrap() {
            return request;
        }

        /**
         * Add HTTP header with the given value.
         */
        public HttpRequestBuilder header(String name, String value) {
            request.header(name, value);
            return this;
        }

        /**
         * Add basic authentication header.
         */
        public HttpRequestBuilder basicAuth(String username, String password) {
            return header("Authorization", "Basic " + Base64.getEncoder()
                    .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8)));
        }

        /**
         * Add SSO session token header.
         */
        public HttpRequestBuilder ssoHeader(String tokenId) {
            return header(WrenAMDefaults.SSO_SESSION_HEADER, tokenId);
        }

        /**
         * Add request body.
         */
        public HttpRequestBuilder body(String method, String body) {
            request.method(method, BodyPublishers.ofString(body));
            return this;
        }

        /**
         * Add POST request body.
         */
        public HttpRequestBuilder postBody(String body) {
            return body("POST", body);
        }

        /**
         * Add JSON POST request body.
         */
        public HttpRequestBuilder postBody(JsonNode body) throws JacksonException {
            return header("Content-Type", "application/json")
                .postBody(objectMapper.writeValueAsString(body));
        }

        /**
         * Finalize and send the request.
         */
        public HttpResponseWrapper buildAndSend() throws InterruptedException, IOException {
            return new HttpResponseWrapper(
                    httpClient.send(request.build(), BodyHandlers.ofByteArray()));
        }

    }

    /**
     * HTTP response wrapper.
     */
    public class HttpResponseWrapper {

        private HttpResponse<byte[]> response;

        private HttpResponseWrapper(HttpResponse<byte[]> response) {
            this.response = response;
        }

        /**
         * Get the raw HTTP response.
         */
        public HttpResponse<byte[]> unwrap() {
            return response;
        }

        /**
         * Check response status code.
         */
        public HttpResponseWrapper checkStatusCode(Consumer<Integer> consumer) {
            consumer.accept(response.statusCode());
            return this;
        }

        /**
         * Assert HTTP response status code value.
         */
        public HttpResponseWrapper assertStatusCode(int expected) {
            checkStatusCode(code -> assertEquals(expected, code, "Unexpected response status code"));
            return this;
        }

        /**
         * Assert HTTP response status code is 2xx.
         */
        public HttpResponseWrapper assertSuccess() {
            checkStatusCode(code ->
                    assertEquals("2xx", (code / 100) + "xx", "Unexpected response status code"));
            return this;
        }

        /**
         * Read string response body.
         */
        public String readStringBody() {
            return new String(response.body(), StandardCharsets.UTF_8);
        }

        /**
         * Read JSON response body.
         */
        public JsonNode readJsonBody() throws JacksonException {
            return objectMapper.readTree(response.body());
        }

    }

    /**
     * Wren:AM CREST authentication handler.
     */
    public class AuthenticationHandler {

        private final URI endpointUri;

        private HttpResponseWrapper currentResponse;

        private JsonNode currentState;

        private AuthenticationHandler(URI endpointUri) {
            this.endpointUri = endpointUri;
        }

        /**
         * Update authentication status based on the current response.
         */
        private AuthenticationHandler updateState() {
            try {
                currentState = currentResponse.readJsonBody();
            } catch (JacksonException e) {
                currentState = NullNode.getInstance(); // invalid response
            }
            return this;
        }

        /**
         * Perform immediate authentication with the given credentials.
         */
        public AuthenticationHandler immediateAuth(String username, String password)
                throws InterruptedException, IOException {
            currentResponse = newHttpRequest(endpointUri)
                    .header("Accept", "application/json")
                    .header("X-OpenAM-Username", username)
                    .header("X-OpenAM-Password", password)
                    .postBody(objectMapper.createObjectNode())
                    .buildAndSend();
            return updateState();
        }

        /**
         * Start new authentication interaction.
         */
        public AuthenticationHandler initializeAuth() throws InterruptedException, IOException {
            currentResponse = newHttpRequest(endpointUri)
                    .header("Accept", "application/json")
                    .postBody(objectMapper.createObjectNode())
                    .buildAndSend();
            return updateState();
        }

        /**
         * Continue authentication interaction using the given callback handler.
         */
        public AuthenticationHandler continueAuth(BiConsumer<String, ArrayNode> callbackHandler)
                throws InterruptedException, IOException {
            if (!currentState.has("callbacks")) {
                throw new IllegalStateException("Missing callback challenge: " + currentState);
            }
            callbackHandler.accept(
                    currentState.get("stage").asString(),
                    currentState.get("callbacks").asArray());
            currentResponse = newHttpRequest(endpointUri)
                    .header("Accept", "application/json")
                    .postBody(currentState)
                    .buildAndSend();
            return updateState();
        }

        /**
         * Get current authentication interaction stage.
         */
        public String getCurrentStage() {
            return currentState.get("stage").asString();
        }

        /**
         * Check if the authentication interaction is in progress.
         */
        public boolean isOngoing() {
            return currentState == null || currentState.has("authId");
        }

        /**
         * Check if the authentication interaction was successful.
         */
        public boolean isSucceeded() {
            return currentState != null && currentState.has("tokenId");
        }

        /**
         * Check if the authentication interaction has failed.
         */
        public boolean isFailed() {
            return !isOngoing() && !isSucceeded()
                    && (currentResponse == null || currentResponse.unwrap().statusCode() >= 400);
        }

        /**
         * Get current authentication state.
         */
        public JsonNode getResultState() {
            return currentState;
        }

        /**
         * Get SSO token ID as a result of a successful authentication.
         */
        public String getSsoTokenId() {
            if (!isSucceeded()) {
                throw new IllegalStateException("Succeeded authentication expected");
            }
            return currentState.get("tokenId").stringValue();
        }

        /**
         * Use the issued SSO token ID as {@link WrenAMClient} session.
         */
        public void useAsSession() {
            WrenAMClient.this.useSsoSession(getSsoTokenId());
        }

    }

}
