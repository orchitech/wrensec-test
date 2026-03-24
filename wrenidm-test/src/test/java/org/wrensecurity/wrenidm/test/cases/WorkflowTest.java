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
package org.wrensecurity.wrenidm.test.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;
import org.testcontainers.containers.ComposeContainer;
import org.wrensecurity.wrenidm.test.base.BaseWrenidmTest;

import tools.jackson.databind.JsonNode;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
/**
 * @deprecated This class needs to be refactored.
 */
public class WorkflowTest extends BaseWrenidmTest {

    private static final int MAX_WORKFLOW_COMPLETE_WAIT_SECONDS = 60;

    private String onboardingDefId;
    private String crudWorkflowId;
    private String rejectWorkflowId;
    private String rejectTaskId;

    private JsonNode waitForWorkflowHistoryDecision(String workflowId, int timeoutSeconds) throws Exception {
        final long deadlineNanos = System.nanoTime()
            + java.util.concurrent.TimeUnit.SECONDS.toNanos(timeoutSeconds);

        String lastBody = null;
        int lastStatus = -1;

        while (System.nanoTime() < deadlineNanos) {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance/history/" + workflowId))
                .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
                .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            lastStatus = resp.statusCode();

            if (lastStatus == 200) {
                lastBody = resp.body();
                JsonNode historyBody = mapper.readTree(lastBody);

                JsonNode decision = historyBody.path("processVariables").path("decision");
                if (decision.isString() && !decision.asString().isBlank()) {
                    return historyBody;
                }
            } else {
                lastBody = resp.body();
            }

            Thread.sleep(500);
        }

        fail("Timed out after " + timeoutSeconds + "s waiting for workflow history decision for workflowId="
            + workflowId + ". Last status=" + lastStatus + ", last response body: " + lastBody);
        return null;
    }

    private static final String MANAGED_USER_DATA = """
        {
          "userName": "workflow",
          "givenName": "John",
          "sn": "Doe",
          "mail": "john.doe@wrensecurity.org",
          "password":"FooBar123"
        }
        """;

    private static final String MANAGED_ROLE_DATA = """
        {
          "name": "employee",
          "description":"Role for employees."
        }
        """;

    private static final String USER_ROLE_WORKFLOW_DATA = """
            {
              "_key": "userRole",
              "userId": "managed/user/workflow",
              "roleId": "managed/role/employee"
            }
            """;

    private static final String APPROVAL_DATA = """
            {
              "result": "approve"
            }
            """;

    private static final String ONBOARDING_WORKFLOW_DATA = """
            {
              "_key": "onboarding",
              "userName": "onboarding",
              "workforceId": "123456",
              "employeeType": "INTERNAL",
              "givenName": "John",
              "sn": "Doe",
              "mail": "john.doe@wrensecurity.org"
            }
            """;

    private static final String CLAIM_DATA = """
            {
              "userId": "openidm-admin"
            }
            """;

    private static final String REJECTION_DATA = """
            {
              "result": "reject"
            }
            """;

    @BeforeAll
    public void init() throws InterruptedException {
        environment = new ComposeContainer(new File("src/test/resources/cases/workflow/compose.yaml"));
        environment.waitingFor(WRENIDM_CONTAINER_NAME, WRENIDM_STARTUP_WAIT_STRATEGY);
        environment.start();
    }

    @AfterAll
    public void teardown() {
        if (environment != null) {
            environment.stop();
        }
    }

    @Test
    @Order(1)
    public void testSetup() throws Exception {
        // Create a managed user for workflow testing
        HttpRequest createUserReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user/workflow"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(MANAGED_USER_DATA))
            .build();
        HttpResponse<String> createUserResp = httpClient.send(createUserReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, createUserResp.statusCode());

        // Create a managed role for workflow testing
        HttpRequest createRoleReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/managed/role/employee"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(MANAGED_ROLE_DATA))
            .build();
        HttpResponse<String> createRoleResp = httpClient.send(createRoleReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, createRoleResp.statusCode());
    }

    @Test
    @Order(2)
    public void testUserRole() throws Exception {
        // Verify user has no roles initially
        HttpRequest checkRolesReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user/workflow/roles?_queryId=query-all-ids"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> checkRolesResp = httpClient.send(checkRolesReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, checkRolesResp.statusCode());
        JsonNode rolesBody = mapper.readTree(checkRolesResp.body());
        assertEquals(0, rolesBody.get("resultCount").asInt());

        // Create user-role assignment workflow
        HttpRequest createWorkflowReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance?_action=create"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(USER_ROLE_WORKFLOW_DATA))
            .build();
        HttpResponse<String> createWorkflowResp = httpClient.send(createWorkflowReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, createWorkflowResp.statusCode());
        JsonNode workflowBody = mapper.readTree(createWorkflowResp.body());
        String workflowId = workflowBody.get("_id").asString();

        // Verify approval task
        HttpRequest getTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance?_queryId=filtered-query&processInstanceId="
                + workflowId + "&taskDefinitionKey=approval"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> getTaskResp = httpClient.send(getTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, getTaskResp.statusCode());
        JsonNode taskBody = mapper.readTree(getTaskResp.body());
        assertEquals(1, taskBody.get("resultCount").asInt());
        assertEquals(workflowId, taskBody.get("result").get(0).get("processInstanceId").asString());
        assertEquals("openidm-admin", taskBody.get("result").get(0).get("assignee").asString());
        String taskId = taskBody.get("result").get(0).get("_id").asString();

        // Approve the task to complete the workflow
        HttpRequest approveTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance/" + taskId + "?_action=complete"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(APPROVAL_DATA))
            .build();
        HttpResponse<String> approveTaskResp = httpClient.send(approveTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, approveTaskResp.statusCode());
        JsonNode approveBody = mapper.readTree(approveTaskResp.body());
        assertEquals("complete", approveBody.path("Task action performed").asString());

        // Wait for workflow to complete and check status
        JsonNode historyBody = waitForWorkflowHistoryDecision(workflowId, MAX_WORKFLOW_COMPLETE_WAIT_SECONDS);
        assertEquals(workflowId, historyBody.get("_id").asString());
        assertEquals("approve", historyBody.path("processVariables").path("decision").asString());

        // Check user roles (should now have employee role)
        HttpRequest checkFinalRolesReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user/workflow/roles?_queryFilter=true"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> checkFinalRolesResp = httpClient.send(checkFinalRolesReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, checkFinalRolesResp.statusCode());
        JsonNode finalRolesBody = mapper.readTree(checkFinalRolesResp.body());
        assertEquals(1, finalRolesBody.get("resultCount").asInt());
        assertEquals("managed/role/employee", finalRolesBody.get("result").get(0).get("_ref").asString());
    }

    @Test
    @Order(3)
    public void testOnboarding() throws Exception {
        // Create onboarding workflow for a new user
        HttpRequest createWorkflowReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance?_action=create"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(ONBOARDING_WORKFLOW_DATA))
            .build();
        HttpResponse<String> createWorkflowResp = httpClient.send(createWorkflowReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, createWorkflowResp.statusCode());
        JsonNode workflowBody = mapper.readTree(createWorkflowResp.body());
        String workflowId = workflowBody.get("_id").asString();

        // Verify approval task
        HttpRequest getTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance?_queryId=filtered-query&processInstanceId="
                + workflowId + "&taskDefinitionKey=approval"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> getTaskResp = httpClient.send(getTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, getTaskResp.statusCode());
        JsonNode taskBody = mapper.readTree(getTaskResp.body());
        assertEquals(1, taskBody.get("resultCount").asInt());
        assertEquals(workflowId, taskBody.get("result").get(0).get("processInstanceId").asString());
        String taskId = taskBody.get("result").get(0).get("_id").asString();

        // Claim task
        HttpRequest claimTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance/" + taskId + "?_action=claim"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(CLAIM_DATA))
            .build();
        HttpResponse<String> claimTaskResp = httpClient.send(claimTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, claimTaskResp.statusCode());
        JsonNode claimBody = mapper.readTree(claimTaskResp.body());
        assertEquals("claim", claimBody.path("Task action performed").asString());

        // Approve task
        HttpRequest approveTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance/" + taskId + "?_action=complete"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(APPROVAL_DATA))
            .build();
        HttpResponse<String> approveTaskResp = httpClient.send(approveTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, approveTaskResp.statusCode());

        // Wait for workflow to complete and check status
        JsonNode historyBody = waitForWorkflowHistoryDecision(workflowId, MAX_WORKFLOW_COMPLETE_WAIT_SECONDS);
        assertEquals(workflowId, historyBody.get("_id").asString());
        assertEquals("approve", historyBody.path("processVariables").path("decision").asString());

        // Verify that the user was successfully created by the workflow
        HttpRequest getUserReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/managed/user/onboarding"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> getUserResp = httpClient.send(getUserReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, getUserResp.statusCode());
        JsonNode userBody = mapper.readTree(getUserResp.body());
        assertEquals("onboarding", userBody.get("_id").asString());
    }

    @Test
    @Order(4)
    public void testProcessDefinitionsQueryAndRead() throws Exception {
        // Query all process definitions to verify workflow deployments
        HttpRequest queryDefsReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processdefinition?_queryId=filtered-query"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> queryDefsResp = httpClient.send(queryDefsReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, queryDefsResp.statusCode());
        JsonNode defsBody = mapper.readTree(queryDefsResp.body());
        assertEquals(2, defsBody.get("resultCount").asInt());

        // Query for specific process definition by key (onboarding)
        HttpRequest getOnboardingDefReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processdefinition?_queryId=filtered-query&key=onboarding"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> getOnboardingDefResp = httpClient.send(getOnboardingDefReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, getOnboardingDefResp.statusCode());
        JsonNode onboardingDefBody = mapper.readTree(getOnboardingDefResp.body());
        assertEquals(1, onboardingDefBody.get("resultCount").asInt());
        assertEquals("onboarding", onboardingDefBody.get("result").get(0).get("key").asString());

        onboardingDefId = onboardingDefBody.get("result").get(0).get("_id").asString();

        // Read specific fields from process definition (form properties, template, diagram)
        HttpRequest readDefFieldsReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processdefinition/" + onboardingDefId
                + "?_fields=formProperties,formGenerationTemplate,diagram"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> readDefFieldsResp = httpClient.send(readDefFieldsReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, readDefFieldsResp.statusCode());
        JsonNode defFieldsBody = mapper.readTree(readDefFieldsResp.body());

        assertTrue(defFieldsBody.get("formGenerationTemplate").asString().startsWith("<div id=\"onboardingForm\""));
        assertTrue(defFieldsBody.get("diagram").asString().startsWith("iVBORw"));
        assertEquals(6, defFieldsBody.get("formProperties").size());
    }

    @Test
    @Order(5)
    public void testProcessInstanceCrud() throws Exception {
        // Create a workflow instance for testing CRUD operations (using modified username to avoid conflicts)
        String createBody = ONBOARDING_WORKFLOW_DATA
            .replace("\"userName\": \"onboarding\"", "\"userName\": \"onboarding-3\"");

        HttpRequest createWorkflowReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance?_action=create"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(createBody))
            .build();
        HttpResponse<String> createWorkflowResp = httpClient.send(createWorkflowReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, createWorkflowResp.statusCode());
        JsonNode workflowBody = mapper.readTree(createWorkflowResp.body());
        crudWorkflowId = workflowBody.get("_id").asString();

        // Query process instance
        HttpRequest queryInstanceReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance?_queryId=filtered-query&processInstanceId="
                + crudWorkflowId))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> queryInstanceResp = httpClient.send(queryInstanceReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, queryInstanceResp.statusCode());
        JsonNode instanceQueryBody = mapper.readTree(queryInstanceResp.body());
        assertEquals(1, instanceQueryBody.get("resultCount").asInt());
        assertEquals(crudWorkflowId, instanceQueryBody.get("result").get(0).get("_id").asString());

        // Read process instance details including variables and tasks
        HttpRequest readInstanceReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance/" + crudWorkflowId))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> readInstanceResp = httpClient.send(readInstanceReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, readInstanceResp.statusCode());
        JsonNode instanceBody = mapper.readTree(readInstanceResp.body());

        assertEquals(crudWorkflowId, instanceBody.get("_id").asString());
        assertEquals("onboarding-3", instanceBody.get("processVariables").get("userName").asString());
        assertEquals(1, instanceBody.get("tasks").size());
        assertEquals("approval", instanceBody.get("tasks").get(0).get("name").asString());

        // Delete the process instance and verify deletion
        HttpRequest deleteInstanceReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance/" + crudWorkflowId))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .DELETE()
            .build();
        HttpResponse<String> deleteInstanceResp = httpClient.send(deleteInstanceReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, deleteInstanceResp.statusCode());
    }

    @Test
    @Order(6)
    public void testDeletedProcessInstanceHistory() throws Exception {
        // Verify the deletion is recorded in history with proper reason
        HttpRequest getDeletedHistoryReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance/history/" + crudWorkflowId))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> getDeletedHistoryResp = httpClient.send(getDeletedHistoryReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, getDeletedHistoryResp.statusCode());
        JsonNode deletedHistoryBody = mapper.readTree(getDeletedHistoryResp.body());

        assertEquals(crudWorkflowId, deletedHistoryBody.get("_id").asString());
        assertEquals("Deleted by Wren:IDM.", deletedHistoryBody.get("deleteReason").asString());
    }

    @Test
    @Order(7)
    public void testTaskInstanceClaimCompleteAndHistoryRejectPath() throws Exception {
        // Create another workflow to test task instance operations (claim, complete, history)
        String createBody = ONBOARDING_WORKFLOW_DATA
            .replace("\"userName\": \"onboarding\"", "\"userName\": \"onboarding-4\"");

        HttpRequest createWorkflowReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/processinstance?_action=create"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(createBody))
            .build();
        HttpResponse<String> createWorkflowResp = httpClient.send(createWorkflowReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, createWorkflowResp.statusCode());
        rejectWorkflowId = mapper.readTree(createWorkflowResp.body()).get("_id").asString();

        // Query for approval task associated with the workflow
        HttpRequest queryTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance?_queryId=filtered-query&processInstanceId="
                + rejectWorkflowId + "&taskDefinitionKey=approval"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> queryTaskResp = httpClient.send(queryTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, queryTaskResp.statusCode());
        JsonNode taskQueryBody = mapper.readTree(queryTaskResp.body());
        assertEquals(1, taskQueryBody.get("resultCount").asInt());
        assertEquals(rejectWorkflowId, taskQueryBody.get("result").get(0).get("processInstanceId").asString());
        rejectTaskId = taskQueryBody.get("result").get(0).get("_id").asString();

        // Read task details including assignee, candidates, and variables
        HttpRequest readTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance/" + rejectTaskId))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> readTaskResp = httpClient.send(readTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, readTaskResp.statusCode());
        JsonNode taskReadBody = mapper.readTree(readTaskResp.body());

        assertEquals(rejectTaskId, taskReadBody.get("_id").asString());
        assertTrue(taskReadBody.get("assignee").isNull());
        assertEquals(1, taskReadBody.get("candidates").get("candidateGroups").size());
        assertEquals("openidm-admin", taskReadBody.get("candidates").get("candidateGroups").get(0).asString());
        assertEquals("onboarding-4", taskReadBody.get("variables").get("userName").asString());

        // Claim the task to assign it to the current user
        HttpRequest claimTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance/" + rejectTaskId + "?_action=claim"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(CLAIM_DATA))
            .build();
        HttpResponse<String> claimTaskResp = httpClient.send(claimTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, claimTaskResp.statusCode());
        assertEquals("claim", mapper.readTree(claimTaskResp.body()).path("Task action performed").asString());

        // Complete the task with rejection decision (testing rejection workflow path)
        HttpRequest completeTaskReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance/" + rejectTaskId + "?_action=complete"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(REJECTION_DATA))
            .build();
        HttpResponse<String> completeTaskResp = httpClient.send(completeTaskReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, completeTaskResp.statusCode());
        assertEquals("complete", mapper.readTree(completeTaskResp.body()).path("Task action performed").asString());

        // Verify task appears in history with completion timestamp
        HttpRequest queryTaskHistoryReq = HttpRequest.newBuilder()
            .uri(URI.create(WRENIDM_BASE_URL + "/openidm/workflow/taskinstance/history?_queryId=filtered-query&processInstanceId="
                + rejectWorkflowId + "&taskDefinitionKey=approval"))
            .header("Authorization", ADMIN_AUTHORIZATION_HEADER_VALUE)
            .build();
        HttpResponse<String> queryTaskHistoryResp = httpClient.send(queryTaskHistoryReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, queryTaskHistoryResp.statusCode());
        JsonNode taskHistoryBody = mapper.readTree(queryTaskHistoryResp.body());

        assertEquals(1, taskHistoryBody.get("resultCount").asInt());
        assertNotNull(taskHistoryBody.get("result").get(0).get("endTime"));

        // Verify workflow completed with rejection decision in history (POLL to avoid race)
        JsonNode history2Body = waitForWorkflowHistoryDecision(rejectWorkflowId, MAX_WORKFLOW_COMPLETE_WAIT_SECONDS);
        assertEquals("reject", history2Body.path("processVariables").path("decision").asString());
        assertEquals("reject", history2Body.path("tasks").get(0).path("taskLocalVariables").path("result").asString());
    }
}
