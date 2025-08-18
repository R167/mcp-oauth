import { Hono } from "hono";
import type { Env, ClientRegistrationRequest } from "../types.js";
import { ClientRegistrationRequestSchema } from "../types.js";
import { StorageManager } from "../managers/StorageManager.js";
import { ScopeValidator } from "../validators/ScopeValidator.js";

const app = new Hono<{ Bindings: Env }>();

// Client registration endpoint
app.post("/register", async (c) => {
  try {
    // Parse and validate request body
    const body = await c.req.json().catch(() => ({}));
    const validationResult = ClientRegistrationRequestSchema.safeParse(body);

    if (!validationResult.success) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "Invalid client registration request",
          details: validationResult.error.issues,
        },
        400,
      );
    }

    const request: ClientRegistrationRequest = validationResult.data;

    // Validate MCP scope format
    const scopeValidator = new ScopeValidator();
    const scopeValidation = scopeValidator.validateScopeFormat(request.scope);

    if (!scopeValidation.isValid || !scopeValidation.mcpScope) {
      return c.json(
        {
          error: "invalid_scope",
          error_description: "Invalid scope format. Must include exactly one mcp:<domain>:<server> scope.",
        },
        400,
      );
    }

    // Validate that the server exists in configuration
    if (!scopeValidator.validateServerExists(scopeValidation.mcpScope)) {
      return c.json(
        {
          error: "invalid_scope",
          error_description: "MCP server not found in configuration.",
        },
        400,
      );
    }

    // Extract domain from validated MCP scope
    const mcpPattern = /^mcp:([^:]+):([^:]+)$/;
    const mcpMatch = scopeValidation.mcpScope.match(mcpPattern);

    if (!mcpMatch) {
      return c.json(
        {
          error: "invalid_scope",
          error_description: "Invalid MCP scope format. Expected: mcp:<domain>:<server>",
        },
        400,
      );
    }

    const mcpDomain = mcpMatch[1];

    // Validate that all redirect URIs are from the same domain as MCP scope
    for (const redirectUri of request.redirect_uris) {
      try {
        const url = new URL(redirectUri);
        if (url.hostname !== mcpDomain) {
          return c.json(
            {
              error: "invalid_redirect_uri",
              error_description: `Redirect URI domain (${url.hostname}) must match MCP scope domain (${mcpDomain})`,
            },
            400,
          );
        }
        // Ensure HTTPS in production
        if (url.protocol !== "https:" && url.hostname !== "localhost" && !url.hostname.startsWith("127.")) {
          return c.json(
            {
              error: "invalid_redirect_uri",
              error_description: "Redirect URIs must use HTTPS except for localhost",
            },
            400,
          );
        }
      } catch (error) {
        return c.json(
          {
            error: "invalid_redirect_uri",
            error_description: `Invalid redirect URI: ${redirectUri}`,
          },
          400,
        );
      }
    }

    // Generate client ID
    const clientId = `mcp_${mcpDomain}_${crypto.randomUUID()}`;

    // Create client registration
    const now = Math.floor(Date.now() / 1000);
    const client = {
      client_id: clientId,
      client_name: request.client_name,
      redirect_uris: request.redirect_uris,
      scope: request.scope,
      created_at: now,
      last_used: now,
      expires_at: now + 60 * 24 * 60 * 60, // 60 days
    };

    // Store client registration
    const storage = new StorageManager(c.env.AUTH_DB);
    await storage.storeRegisteredClient(client);

    // Return client registration response
    return c.json(
      {
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        scope: client.scope,
        expires_at: client.expires_at,
        registration_client_uri: `${c.env.WORKER_BASE_URL || ""}/client/${client.client_id}`,
      },
      201,
    );
  } catch (error) {
    console.error("Client registration error:", error);
    return c.json(
      {
        error: "server_error",
        error_description: "Internal server error",
      },
      500,
    );
  }
});

// Get client information
app.get("/client/:client_id", async (c) => {
  try {
    const clientId = c.req.param("client_id");

    const storage = new StorageManager(c.env.AUTH_DB);
    const client = await storage.getRegisteredClient(clientId);

    if (!client) {
      return c.json(
        {
          error: "invalid_client",
          error_description: "Client not found or expired",
        },
        404,
      );
    }

    return c.json({
      client_id: client.client_id,
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      scope: client.scope,
      created_at: client.created_at,
      last_used: client.last_used,
      expires_at: client.expires_at,
    });
  } catch (error) {
    console.error("Client lookup error:", error);
    return c.json(
      {
        error: "server_error",
        error_description: "Internal server error",
      },
      500,
    );
  }
});

export { app as ClientRegistrationHandler };
