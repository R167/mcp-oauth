import { Environment, AuthServerMetadata } from "../types";
import { ScopeValidator } from "../utils/scopes";

export class MetadataHandler {
	private scopeValidator: ScopeValidator;

	constructor(private env: Environment) {
		this.scopeValidator = new ScopeValidator();
	}

	async handleAuthorizationServerMetadata(request: Request): Promise<Response> {
		try {
			const metadata: AuthServerMetadata = {
				issuer: this.env.WORKER_BASE_URL,
				authorization_endpoint: `${this.env.WORKER_BASE_URL}/authorize`,
				token_endpoint: `${this.env.WORKER_BASE_URL}/token`,
				response_types_supported: ["code"],
				grant_types_supported: ["authorization_code", "refresh_token"],
				subject_types_supported: ["public"],
				id_token_signing_alg_values_supported: ["RS256"],
				scopes_supported: this.getSupportedScopes(),
				token_endpoint_auth_methods_supported: ["none"],
				code_challenge_methods_supported: ["S256"],
			};

			return new Response(JSON.stringify(metadata, null, 2), {
				headers: {
					"Content-Type": "application/json",
					"Cache-Control": "public, max-age=3600",
				},
			});
		} catch (error) {
			console.error("Metadata error:", error);
			return new Response("Internal Server Error", { status: 500 });
		}
	}

	async handleJWKS(request: Request): Promise<Response> {
		try {
			const publicKey = await this.importPublicKey(this.env.JWT_PUBLIC_KEY);
			const jwk = await this.publicKeyToJWK(publicKey);

			const jwks = {
				keys: [
					{
						...jwk,
						kid: "mcp-oauth-key-1",
						use: "sig",
						alg: "RS256",
					},
				],
			};

			return new Response(JSON.stringify(jwks, null, 2), {
				headers: {
					"Content-Type": "application/json",
					"Cache-Control": "public, max-age=86400",
				},
			});
		} catch (error) {
			console.error("JWKS error:", error);
			return new Response("Internal Server Error", { status: 500 });
		}
	}

	async handleProtectedResourceMetadata(request: Request): Promise<Response> {
		try {
			const url = new URL(request.url);
			const resource = url.searchParams.get("resource");

			if (!resource) {
				return new Response("Missing resource parameter", { status: 400 });
			}

			let domain: string;
			let server: string;

			try {
				const resourceUrl = new URL(resource);
				domain = resourceUrl.hostname;
				server = resourceUrl.pathname.split("/").filter(Boolean)[0] || "default";
			} catch {
				return new Response("Invalid resource URL", { status: 400 });
			}

			const serverConfig = this.scopeValidator.getServerConfig(domain, server);
			if (!serverConfig) {
				return new Response("Resource not found", { status: 404 });
			}

			const metadata = {
				resource,
				authorization_servers: [this.env.WORKER_BASE_URL],
				scopes_supported: [`mcp:${domain}:${server}`, "user:email"],
				bearer_methods_supported: ["header"],
				resource_documentation: serverConfig.description || `MCP server at ${domain}:${server}`,
			};

			return new Response(JSON.stringify(metadata, null, 2), {
				headers: {
					"Content-Type": "application/json",
					"Cache-Control": "public, max-age=3600",
				},
			});
		} catch (error) {
			console.error("Protected resource metadata error:", error);
			return new Response("Internal Server Error", { status: 500 });
		}
	}

	private getSupportedScopes(): string[] {
		const servers = this.scopeValidator.getAllServers();
		const mcpScopes = servers.map((server) => `mcp:${server.domain}:${server.server}`);
		return [...mcpScopes, "user:email"];
	}

	private async importPublicKey(pemKey: string): Promise<CryptoKey> {
		const binaryDer = this.pemToBinary(pemKey);
		return await crypto.subtle.importKey(
			"spki",
			binaryDer,
			{
				name: "RSASSA-PKCS1-v1_5",
				hash: "SHA-256",
			},
			true,
			["verify"],
		);
	}

	private pemToBinary(pem: string): ArrayBuffer {
		const base64 = pem
			.replace(/-----BEGIN PUBLIC KEY-----/, "")
			.replace(/-----END PUBLIC KEY-----/, "")
			.replace(/\\s/g, "");

		const binaryString = atob(base64);
		const bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) {
			bytes[i] = binaryString.charCodeAt(i);
		}
		return bytes.buffer;
	}

	private async publicKeyToJWK(publicKey: CryptoKey): Promise<any> {
		const exported = await crypto.subtle.exportKey("jwk", publicKey);
		return {
			kty: exported.kty,
			n: exported.n,
			e: exported.e,
		};
	}
}

export class DiscoveryHandler {
	constructor(private env: Environment) {}

	async handleWellKnownOAuth(request: Request): Response {
		const authServerUrl = `${this.env.WORKER_BASE_URL}/.well-known/oauth-authorization-server`;
		return Response.redirect(authServerUrl, 302);
	}

	async handleWellKnownOpenIDConfiguration(request: Request): Response {
		const metadata = {
			issuer: this.env.WORKER_BASE_URL,
			authorization_endpoint: `${this.env.WORKER_BASE_URL}/authorize`,
			token_endpoint: `${this.env.WORKER_BASE_URL}/token`,
			jwks_uri: `${this.env.WORKER_BASE_URL}/.well-known/jwks.json`,
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: ["RS256"],
			scopes_supported: ["openid", "email"],
			token_endpoint_auth_methods_supported: ["none"],
			code_challenge_methods_supported: ["S256"],
		};

		return new Response(JSON.stringify(metadata, null, 2), {
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "public, max-age=3600",
			},
		});
	}

	async handleServerInfo(request: Request): Response {
		const info = {
			name: "MCP OAuth Authorization Server",
			version: "1.0.0",
			description: "OAuth 2.1 Authorization Server for Model Context Protocol (MCP) resources",
			issuer: this.env.WORKER_BASE_URL,
			endpoints: {
				authorization: `${this.env.WORKER_BASE_URL}/authorize`,
				token: `${this.env.WORKER_BASE_URL}/token`,
				metadata: `${this.env.WORKER_BASE_URL}/.well-known/oauth-authorization-server`,
				jwks: `${this.env.WORKER_BASE_URL}/.well-known/jwks.json`,
			},
			features: [
				"OAuth 2.1 with PKCE",
				"MCP scope validation",
				"GitHub identity provider",
				"Encrypted refresh tokens",
				"Key rotation support",
			],
		};

		return new Response(JSON.stringify(info, null, 2), {
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "public, max-age=3600",
			},
		});
	}
}
