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

/**
 * Common default Wren:AM test constants.
 */
public final class WrenAMDefaults {

    private WrenAMDefaults() {
    }

    /**
     * Default Wren:DS image for config and user stores.
     */
    public static final String WRENDS_IMAGE_NAME = "wrensecurity/wrends:5.0.1";

    /**
     * Default HAProxy image.
     */
    public static final String HAPROXY_IMAGE_NAME = "haproxy:2.7.8";

    /**
     * Default Wren:AM image name to be tested.
     */
    public static final String WRENAM_IMAGE_NAME = "wrenam:local";

    /**
     * Default Wren:AM deployment URI.
     */
    public static final String DEPLOYMENT_URI = "/auth";

    /**
     * Default Wren:AM admin username.
     */
    public static final String ADMIN_USERNAME = "amadmin";

    /**
     * Default Wren:AM admin password.
     */
    public static final String ADMIN_PASSWORD = "password";

    /**
     * Default config store root suffix.
     */
    public static final String CONFIG_STORE_BASE_DN = "ou=wrenam,dc=wrensecurity,dc=org";

    /**
     * Default user store base DN.
     */
    public static final String USER_STORE_BASE_DN = "dc=example,dc=org";

    /**
     * Default SSO session cookie / header name.
     */
    public static final String SSO_SESSION_HEADER = "iPlanetDirectoryPro";

}
