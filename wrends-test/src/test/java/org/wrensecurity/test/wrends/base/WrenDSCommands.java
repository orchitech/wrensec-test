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

import static org.junit.jupiter.api.Assertions.fail;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_PASSWORD;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.testcontainers.containers.Container.ExecResult;
import org.wrensecurity.test.base.wrends.WrenDSContainer;

/**
 * Static helper for common Wren:DS CLI commands executed inside containers.
 */
public final class WrenDSCommands {

    private WrenDSCommands() {
    }

    /**
     * Run dsconfig with standard bind arguments and additional subcommand arguments.
     */
    public static ExecResult dsconfig(WrenDSContainer container, String... subcommandArgs)
            throws IOException, InterruptedException {
        List<String> args = new ArrayList<>(List.of(
                "dsconfig",
                "--hostname", "localhost",
                "--port", "4444",
                "--trustAll",
                "--bindDN", ROOT_USER_DN,
                "--bindPassword", ROOT_USER_PASSWORD,
                "--no-prompt"));
        args.addAll(Arrays.asList(subcommandArgs));
        return container.execInContainer(args.toArray(String[]::new));
    }

    /**
     * Run ldapsearch inside the container with standard bind arguments.
     */
    public static ExecResult ldapSearch(WrenDSContainer container, String baseDN, String filter,
            String... attrs) throws IOException, InterruptedException {
        List<String> args = new ArrayList<>(List.of(
                "ldapsearch",
                "--port", "1389",
                "--bindDN", ROOT_USER_DN,
                "--bindPassword", ROOT_USER_PASSWORD,
                "--baseDN", baseDN,
                filter));
        args.addAll(Arrays.asList(attrs));
        return container.execInContainer(args.toArray(String[]::new));
    }

    /**
     * Run ldapdelete inside the container with standard bind arguments.
     */
    public static ExecResult ldapDelete(WrenDSContainer container, String dn)
            throws IOException, InterruptedException {
        return container.execInContainer(
                "ldapdelete",
                "--port", "1389",
                "--bindDN", ROOT_USER_DN,
                "--bindPassword", ROOT_USER_PASSWORD,
                dn);
    }

    /**
     * Run ldapmodify over plain LDAP (port 1389) inside the container.
     */
    public static ExecResult ldapModify(WrenDSContainer container, String filePath)
            throws IOException, InterruptedException {
        return container.execInContainer(
                "ldapmodify",
                "--port", "1389",
                "--bindDN", ROOT_USER_DN,
                "--bindPassword", ROOT_USER_PASSWORD,
                "--filename", filePath);
    }

    /**
     * Assert that the exec result has exit code 0, or fail with a message.
     */
    public static void assertSuccess(ExecResult result, String message) {
        if (result.getExitCode() != 0) {
            fail(message + " (exit code " + result.getExitCode() + "): " + result.getStderr());
        }
    }

}
