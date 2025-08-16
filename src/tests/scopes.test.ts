import { describe, it, expect } from 'vitest';
import { ScopeValidator } from '../utils/scopes';

describe('ScopeValidator', () => {
  const validator = new ScopeValidator();

  describe('parseMCPScope', () => {
    it('should parse valid MCP scope', () => {
      const result = validator.parseMCPScope('mcp:example.com:filesystem');
      expect(result).toEqual({
        type: 'mcp',
        domain: 'example.com',
        server: 'filesystem',
        raw: 'mcp:example.com:filesystem'
      });
    });

    it('should return null for invalid scope format', () => {
      expect(validator.parseMCPScope('invalid:scope')).toBeNull();
      expect(validator.parseMCPScope('mcp:domain')).toBeNull();
      expect(validator.parseMCPScope('mcp:domain:server:extra')).toBeNull();
    });
  });

  describe('validateScopeFormat', () => {
    it('should accept valid scope combinations', () => {
      const result = validator.validateScopeFormat(['mcp:example.com:filesystem', 'user:email']);
      expect(result.valid).toBe(true);
    });

    it('should reject multiple MCP scopes', () => {
      const result = validator.validateScopeFormat([
        'mcp:example.com:filesystem', 
        'mcp:example.com:database'
      ]);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Only one MCP scope is allowed');
    });

    it('should reject requests without MCP scope', () => {
      const result = validator.validateScopeFormat(['user:email']);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('At least one MCP scope is required');
    });

    it('should reject invalid non-MCP scopes', () => {
      const result = validator.validateScopeFormat(['mcp:example.com:filesystem', 'invalid:scope']);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid scope: invalid:scope');
    });
  });

  describe('validateDomainMatchesRedirect', () => {
    it('should accept matching domains', () => {
      const result = validator.validateDomainMatchesRedirect(
        'mcp:example.com:filesystem',
        'https://example.com/callback'
      );
      expect(result.valid).toBe(true);
    });

    it('should reject mismatched domains', () => {
      const result = validator.validateDomainMatchesRedirect(
        'mcp:example.com:filesystem',
        'https://different.com/callback'
      );
      expect(result.valid).toBe(false);
      expect(result.error).toContain('domain');
    });
  });

  describe('validateServerExists', () => {
    it('should accept configured servers', () => {
      const result = validator.validateServerExists('mcp:example.com:filesystem');
      expect(result.valid).toBe(true);
    });

    it('should reject unconfigured servers', () => {
      const result = validator.validateServerExists('mcp:unknown.com:server');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('not configured');
    });
  });

  describe('validateUserAccess', () => {
    it('should accept authorized users', () => {
      const result = validator.validateUserAccess('mcp:example.com:filesystem', 'alice');
      expect(result.valid).toBe(true);
    });

    it('should reject unauthorized users', () => {
      const result = validator.validateUserAccess('mcp:example.com:filesystem', 'unauthorized');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('not authorized');
    });
  });
});