import { Environment } from '../types';

export class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EncryptionError';
  }
}

export interface EncryptedData {
  data: string;
  iv: string;
  keyVersion: string;
}

export class EncryptionManager {
  constructor(private env: Environment) {}

  private async getEncryptionKey(keyVersion: string = 'current'): Promise<CryptoKey> {
    let keyMaterial: string;
    
    if (keyVersion === 'current') {
      keyMaterial = this.env.REFRESH_ENCRYPTION_KEY;
    } else {
      const storedKey = await this.env.AUTH_KV.get(`encryption_key:${keyVersion}`);
      if (!storedKey) {
        throw new EncryptionError(`Encryption key version ${keyVersion} not found`);
      }
      keyMaterial = storedKey;
    }

    const keyBytes = new TextEncoder().encode(keyMaterial);
    const keyHash = await crypto.subtle.digest('SHA-256', keyBytes);
    
    return await crypto.subtle.importKey(
      'raw',
      keyHash,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async encrypt(data: string, keyVersion: string = 'current'): Promise<EncryptedData> {
    try {
      const key = await this.getEncryptionKey(keyVersion);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encodedData = new TextEncoder().encode(data);

      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encodedData
      );

      const encryptedArray = new Uint8Array(encryptedBuffer);
      const encryptedBase64 = btoa(String.fromCharCode(...encryptedArray));
      const ivBase64 = btoa(String.fromCharCode(...iv));

      return {
        data: encryptedBase64,
        iv: ivBase64,
        keyVersion
      };
    } catch (error) {
      throw new EncryptionError(`Encryption failed: ${error}`);
    }
  }

  async decrypt(encryptedData: EncryptedData): Promise<string> {
    try {
      const key = await this.getEncryptionKey(encryptedData.keyVersion);
      
      const encryptedBytes = new Uint8Array(
        atob(encryptedData.data).split('').map(char => char.charCodeAt(0))
      );
      const iv = new Uint8Array(
        atob(encryptedData.iv).split('').map(char => char.charCodeAt(0))
      );

      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encryptedBytes
      );

      return new TextDecoder().decode(decryptedBuffer);
    } catch (error) {
      throw new EncryptionError(`Decryption failed: ${error}`);
    }
  }

  async rotateKey(newKeyMaterial: string): Promise<string> {
    const newVersion = `v${Date.now()}`;
    
    await this.env.AUTH_KV.put(
      `encryption_key:${newVersion}`,
      newKeyMaterial,
      { expirationTtl: 365 * 24 * 3600 }
    );

    return newVersion;
  }

  async listKeyVersions(): Promise<string[]> {
    const list = await this.env.AUTH_KV.list({ prefix: 'encryption_key:' });
    return list.keys.map(key => key.name.replace('encryption_key:', ''));
  }
}

export function encodeEncryptedData(data: EncryptedData): string {
  return btoa(JSON.stringify(data));
}

export function decodeEncryptedData(encoded: string): EncryptedData {
  try {
    return JSON.parse(atob(encoded));
  } catch (error) {
    throw new EncryptionError('Invalid encrypted data format');
  }
}