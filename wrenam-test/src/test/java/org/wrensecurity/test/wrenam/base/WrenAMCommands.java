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

import static org.wrensecurity.test.base.support.CustomAssertions.assertSuccess;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.ContainerState;
import org.testcontainers.containers.ExecConfig;
import org.testcontainers.images.builder.Transferable;

/**
 * Static helper for common Wren:AM CLI commands executed inside containers.
 */
public final class WrenAMCommands {

    private static final String SSOADM_PASSWORD_PATH = "/srv/wrenam/ssoadm.pwd";

    private WrenAMCommands() {
    }

    /**
     * Run ssoadm command with standard amAdmin credentials.
     */
    public static ExecResult ssoadm(ContainerState container, String command, String... options)
            throws IOException, InterruptedException {
        container.copyFileToContainer(
                Transferable.of(WrenAMDefaults.ADMIN_PASSWORD, 0400),
                SSOADM_PASSWORD_PATH);
        ExecResult chownResult = container.execInContainer(ExecConfig.builder()
                .user("0")
                .command(new String[] { "chown", "1000:1000", SSOADM_PASSWORD_PATH })
                .build());
        assertSuccess(chownResult, "Unable to change password file ownership");

        List<String> args = new ArrayList<>(List.of(
                "ssoadm",
                command,
                "--adminid", WrenAMDefaults.ADMIN_USERNAME,
                "--password-file", SSOADM_PASSWORD_PATH));
        args.addAll(Arrays.asList(options));
        return container.execInContainer(args.toArray(String[]::new));
    }

}
