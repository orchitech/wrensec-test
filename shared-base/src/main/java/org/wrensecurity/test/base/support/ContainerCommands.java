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

package org.wrensecurity.test.base.support;

import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.ExecCreateCmdResponse;
import org.testcontainers.containers.ContainerState;

/**
 * Common base container commands.
 */
public class ContainerCommands {

    private ContainerCommands() {
    }

    /**
     * Execute command with root privileges.
     */
    public static void execAsRoot(ContainerState container, String... command) throws InterruptedException {
        ExecCreateCmdResponse execCreateCmdResponse = container.getDockerClient()
            .execCreateCmd(container.getContainerId())
            .withUser("0")
            .withAttachStdout(true)
            .withAttachStderr(true)
            .withCmd(command)
            .exec();

        container.getDockerClient()
            .execStartCmd(execCreateCmdResponse.getId())
            .exec(new ResultCallback.Adapter<>())
            .awaitCompletion();
    }

}
