import { Environment } from "./types";
import { AuthorizeHandler } from "./handlers/authorize";
import { TokenHandler } from "./handlers/token";
import { MetadataHandler, DiscoveryHandler } from "./handlers/metadata";

export default {
	async fetch(request: Request, env: Environment, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const pathname = url.pathname;

		try {
			if (!env.WORKER_BASE_URL) {
				env.WORKER_BASE_URL = `${url.protocol}//${url.host}`;
			}

			const corsHeaders = {
				"Access-Control-Allow-Origin": "*",
				"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type, Authorization",
				"Access-Control-Max-Age": "86400",
			};

			if (request.method === "OPTIONS") {
				return new Response(null, {
					status: 204,
					headers: corsHeaders,
				});
			}

			let response: Response;

			switch (pathname) {
				case "/":
					response = await new DiscoveryHandler(env).handleServerInfo(request);
					break;

				case "/authorize":
					response = await new AuthorizeHandler(env).handle(request);
					break;

				case "/token":
					response = await new TokenHandler(env).handle(request);
					break;

				case "/auth/github/callback":
					response = await new AuthorizeHandler(env).handleGitHubCallback(request);
					break;

				case "/.well-known/oauth-authorization-server":
					response = await new MetadataHandler(env).handleAuthorizationServerMetadata(request);
					break;

				case "/.well-known/openid_configuration":
					response = await new DiscoveryHandler(env).handleWellKnownOpenIDConfiguration(request);
					break;

				case "/.well-known/jwks.json":
					response = await new MetadataHandler(env).handleJWKS(request);
					break;

				case "/protected-resource-metadata":
					response = await new MetadataHandler(env).handleProtectedResourceMetadata(request);
					break;

				case "/health":
					response = await handleHealth(request, env);
					break;

				case "/admin/revoke":
					response = await handleTokenRevocation(request, env);
					break;

				default:
					response = new Response("Not Found", {
						status: 404,
						headers: { "Content-Type": "text/plain" },
					});
			}

			Object.entries(corsHeaders).forEach(([key, value]) => {
				response.headers.set(key, value);
			});

			return response;
		} catch (error) {
			console.error("Worker error:", error);

			return new Response(
				JSON.stringify({
					error: "server_error",
					error_description: "Internal server error",
				}),
				{
					status: 500,
					headers: {
						"Content-Type": "application/json",
						"Cache-Control": "no-store",
						...corsHeaders,
					},
				},
			);
		}
	},
};

async function handleHealth(request: Request, env: Environment): Promise<Response> {
	try {
		const kvTest = await env.AUTH_KV.put("health-check", "ok", { expirationTtl: 60 });
		const kvGet = await env.AUTH_KV.get("health-check");

		const health = {
			status: "healthy",
			timestamp: new Date().toISOString(),
			version: "1.0.0",
			services: {
				kv: kvGet === "ok" ? "healthy" : "unhealthy",
				jwt: env.JWT_PRIVATE_KEY && env.JWT_PUBLIC_KEY ? "configured" : "missing_keys",
				github: env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET ? "configured" : "missing_config",
				encryption: env.REFRESH_ENCRYPTION_KEY ? "configured" : "missing_key",
			},
		};

		const overallHealthy = Object.values(health.services).every((status) => status === "healthy" || status === "configured");

		return new Response(JSON.stringify(health, null, 2), {
			status: overallHealthy ? 200 : 503,
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "no-cache",
			},
		});
	} catch (error) {
		console.error("Health check error:", error);
		return new Response(
			JSON.stringify({
				status: "unhealthy",
				error: "Health check failed",
			}),
			{
				status: 503,
				headers: {
					"Content-Type": "application/json",
					"Cache-Control": "no-cache",
				},
			},
		);
	}
}

async function handleTokenRevocation(request: Request, env: Environment): Promise<Response> {
	try {
		if (request.method !== "POST") {
			return new Response("Method Not Allowed", { status: 405 });
		}

		const authHeader = request.headers.get("Authorization");
		if (!authHeader || !authHeader.startsWith("Bearer ")) {
			return new Response("Unauthorized", { status: 401 });
		}

		const formData = await request.formData();
		const userId = formData.get("user_id") as string;
		const tokenType = formData.get("token_type") as string;

		if (!userId) {
			return new Response("user_id is required", { status: 400 });
		}

		const storage = new (await import("./utils/storage")).StorageManager(env);

		if (tokenType === "all" || !tokenType) {
			await storage.revokeAllUserTokens(userId);
			return new Response("All tokens revoked", { status: 200 });
		}

		return new Response("Invalid token_type", { status: 400 });
	} catch (error) {
		console.error("Token revocation error:", error);
		return new Response("Internal Server Error", { status: 500 });
	}
}

export { Environment };
