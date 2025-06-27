import { createDecipheriv, scrypt, pbkdf2 } from "crypto";
import { readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { promisify } from "util";
import { getPassword, clearSensitiveData } from "./utils.js";

const scryptAsync = promisify(scrypt);
const pbkdf2Async = promisify(pbkdf2);

interface EncryptedData {
  algorithm: string;
  keyDerivation: string;
  salt: string;
  iv: string;
  data: string;
  timestamp: number;
  authTag?: string; // for GCM mode
  version?: string;
}

export async function decryptFile(inputPath: string, outputPath: string, password: string | null, force: boolean = false): Promise<void> {
  let key: Buffer | null = null;
  let decryptionPassword: string | null = null;

  try {
    // Check if input file exists
    if (!existsSync(inputPath)) {
      throw new Error(`Encrypted file not found: ${inputPath}`);
    }

    // Check if output file exists
    if (!force && existsSync(outputPath)) {
      throw new Error(`Output file already exists: ${outputPath}. Use --force to overwrite`);
    }

    // Read encrypted data
    const encryptedContent = await readFile(inputPath, "utf8");
    let encryptedData: EncryptedData;

    try {
      encryptedData = JSON.parse(encryptedContent);
    } catch (parseError) {
      throw new Error("Invalid encrypted file format");
    }

    // Validate encrypted data structure
    if (!encryptedData.algorithm || !encryptedData.data || !encryptedData.salt || !encryptedData.iv) {
      throw new Error("Corrupted encrypted file - missing required fields");
    }

    // Get password
    decryptionPassword = password || (await getPassword("Enter decryption password: "));

    if (!decryptionPassword) {
      throw new Error("Password is required for decryption");
    }

    // Convert salt and IV from hex to buffer
    const salt = Buffer.from(encryptedData.salt, "hex");
    const iv = Buffer.from(encryptedData.iv, "hex");

    // Recreate the key
    try {
      if (encryptedData.keyDerivation === "scrypt") {
        key = (await scryptAsync(decryptionPassword, salt, 32)) as Buffer;
      } else if (encryptedData.keyDerivation === "argon2") {
        // Use pbkdf2 as fallback for argon2
        key = (await pbkdf2Async(decryptionPassword, salt, 100000, 32, "sha512")) as Buffer;
      } else {
        // Default to pbkdf2
        key = (await pbkdf2Async(decryptionPassword, salt, 100000, 32, "sha512")) as Buffer;
      }
    } catch (keyError: any) {
      throw new Error(`Failed to derive encryption key: ${keyError.message}`);
    }

    // Decrypt the data
    let decrypted: string;
    try {
      const decipher = createDecipheriv(encryptedData.algorithm, key, iv);

      // Handle authentication tag for GCM mode
      if (encryptedData.authTag && encryptedData.algorithm.toLowerCase().includes("gcm")) {
        const authTag = Buffer.from(encryptedData.authTag, "hex");
        // Type assertion to allow setAuthTag for GCM mode
        (decipher as import("crypto").DecipherGCM).setAuthTag(authTag);
      }

      decrypted = decipher.update(encryptedData.data, "hex", "utf8");
      decrypted += decipher.final("utf8");
    } catch (decryptError: any) {
      if (
        decryptError.message.includes("bad decrypt") ||
        decryptError.message.includes("wrong final block length") ||
        decryptError.message.includes("Unsupported state") ||
        decryptError.message.includes("invalid tag")
      ) {
        throw new Error("Invalid password or corrupted file");
      }
      throw new Error(`Decryption failed: ${decryptError.message}`);
    }

    // Validate decrypted content
    if (!decrypted || decrypted.trim().length === 0) {
      throw new Error("Decryption resulted in empty content");
    }

    // Save the result
    await writeFile(outputPath, decrypted, "utf8");
  } catch (error: any) {
    // Clean up any sensitive data from memory
    if (key) clearSensitiveData(key);
    if (decryptionPassword) clearSensitiveData(decryptionPassword);

    // Handle specific error types
    if (error.code === "ENOENT") {
      throw new Error(`File not found: ${inputPath}`);
    } else if (error.code === "EACCES") {
      throw new Error(`Permission denied: ${error.path}`);
    } else if (error.code === "ENOSPC") {
      throw new Error(`No space left on device`);
    }

    if (typeof error.message === "string") {
      throw new Error(error.message);
    }
    throw new Error(`Decryption error: ${error.toString()}`);
  } finally {
    // Always clean up sensitive data
    if (key) clearSensitiveData(key);
    if (decryptionPassword) clearSensitiveData(decryptionPassword);
  }
}

/**
 * Additional utility function for verification
 */
export async function verifyDecryption(inputPath: string, password: string): Promise<boolean> {
  try {
    const encryptedContent = await readFile(inputPath, "utf8");
    const encryptedData: EncryptedData = JSON.parse(encryptedContent);

    const salt = Buffer.from(encryptedData.salt, "hex");
    const iv = Buffer.from(encryptedData.iv, "hex");

    let key: Buffer;
    if (encryptedData.keyDerivation === "scrypt") {
      key = (await scryptAsync(password, salt, 32)) as Buffer;
    } else {
      key = (await pbkdf2Async(password, salt, 100000, 32, "sha512")) as Buffer;
    }

    const decipher = createDecipheriv(encryptedData.algorithm, key, iv);

    // Handle authentication tag for GCM mode
    if (encryptedData.authTag && encryptedData.algorithm.toLowerCase().includes("gcm")) {
      const authTag = Buffer.from(encryptedData.authTag, "hex");
      (decipher as import("crypto").DecipherGCM).setAuthTag(authTag);
    }

    decipher.update(encryptedData.data, "hex", "utf8");
    decipher.final("utf8");

    // Clean up sensitive data
    clearSensitiveData(key);

    return true;
  } catch {
    return false;
  }
}

/**
 * Get encrypted file information without decrypting
 */
export async function getEncryptedFileInfo(filePath: string): Promise<Partial<EncryptedData>> {
  try {
    const content = await readFile(filePath, "utf8");
    const data: EncryptedData = JSON.parse(content);

    // Return only non-sensitive information
    return {
      algorithm: data.algorithm,
      keyDerivation: data.keyDerivation,
      timestamp: data.timestamp,
      version: data.version || "unknown",
    };
  } catch (error: any) {
    throw new Error(`Cannot read file information: ${error.message}`);
  }
}

/**
 * Check if file is a valid encrypted file
 */
export async function isValidEncryptedFile(filePath: string): Promise<boolean> {
  try {
    const info = await getEncryptedFileInfo(filePath);
    return !!(info.algorithm && info.keyDerivation);
  } catch {
    return false;
  }
}
