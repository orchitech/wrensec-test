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
package org.wrensecurity.test.wrends.base;

/**
 * Common shared test constants.
 */
public final class WrenDSConstants {

    private WrenDSConstants() {
    }

    /**
     * Default Wren:DS image name to be tested.
     */
    public static final String WRENDS_IMAGE_NAME = "wrends:local";

    /**
     * Default root user DN.
     */
    public static final String ROOT_USER_DN = "cn=Directory Manager";

    /**
     * Default root user password.
     */
    public static final String ROOT_USER_PASSWORD = "password";

    /**
     * Default base DN.
     */
    public static final String BASE_DN = "dc=example,dc=com";

}
