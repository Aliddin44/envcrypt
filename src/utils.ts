import crypto from "crypto";
import argon2 from "argon2";
import { createInterface } from "readline";
import { stdin, stdout } from "process";

const ALGORITHM = "aes-256-cbc";

export async function generateKey(password: string, salt: Buffer, algo: "argon2" | "scrypt" = "argon2"): Promise<Buffer> {
  if (algo === "argon2") {
    return await argon2.hash(password, {
      type: argon2.argon2id,
      salt,
      hashLength: 32,
      raw: true,
      memoryCost: 2 ** 16,
      timeCost: 5,
      parallelism: 1,
    });
  } else if (algo === "scrypt") {
    return crypto.scryptSync(password, salt, 32);
  }
  throw new Error(`Unknown algorithm: ${algo}`);
}

export async function encrypt(text: string, password: string, algo: "argon2" | "scrypt" = "argon2"): Promise<string> {
  const iv = crypto.randomBytes(16);
  const salt = crypto.randomBytes(16);
  const key = await generateKey(password, salt, algo);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return [algo, salt.toString("hex"), iv.toString("hex"), encrypted.toString("hex")].join(":");
}

export async function decrypt(data: string, password: string): Promise<string> {
  const [algoStr, saltHex, ivHex, encryptedHex] = data.split(":");
  const algo = algoStr as "argon2" | "scrypt";
  const salt = Buffer.from(saltHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");
  const key = await generateKey(password, salt, algo);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString();
}

/**
 * Secure password input - FIXED VERSION
 */
export async function getPassword(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    let password = "";
    let isRawMode = false;

    // Display prompt
    stdout.write(prompt);

    try {
      // Check if we're in a TTY (interactive terminal)
      if (!stdin.isTTY) {
        // Non-interactive mode - read from stdin normally
        const rl = createInterface({ input: stdin, output: stdout });
        rl.question("", (answer) => {
          rl.close();
          resolve(answer);
        });
        return;
      }

      // Interactive mode - hide password input
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding("utf8");
      isRawMode = true;

      const onData = (chunk: Buffer | string) => {
        const data = chunk.toString();

        for (let i = 0; i < data.length; i++) {
          const char = data[i];
          const charCode = char.charCodeAt(0);

          switch (charCode) {
            case 3: // Ctrl+C
              cleanup();
              process.exit(0);
              break;

            case 13: // Enter
            case 10: // Line Feed
              cleanup();
              stdout.write("\n");
              resolve(password);
              return;

            case 127: // Backspace
            case 8: // Backspace (Windows)
              if (password.length > 0) {
                password = password.slice(0, -1);
                stdout.write("\b \b");
              }
              break;

            case 4: // Ctrl+D
              cleanup();
              stdout.write("\n");
              resolve(password);
              return;

            default:
              // Only accept printable ASCII characters
              if (charCode >= 32 && charCode <= 126) {
                password += char;
                stdout.write("*");
              }
              break;
          }
        }
      };

      const onError = (error: Error) => {
        cleanup();
        reject(error);
      };

      const cleanup = () => {
        if (isRawMode && stdin.isTTY) {
          stdin.setRawMode(false);
        }
        stdin.removeListener("data", onData);
        stdin.removeListener("error", onError);
        stdin.pause();
      };

      stdin.on("data", onData);
      stdin.on("error", onError);
    } catch (error) {
      if (isRawMode && stdin.isTTY) {
        stdin.setRawMode(false);
      }
      reject(error);
    }
  });
}

export function validateEnvFile(content: string): boolean {
  if (!content || !content.trim()) {
    return false;
  }

  // At least one valid KEY=VALUE line must exist
  const lines = content.split("\n");
  return lines.some((line) => {
    const trimmed = line.trim();
    return (
      trimmed && !trimmed.startsWith("#") && trimmed.includes("=") && trimmed.indexOf("=") > 0 // KEY must not be empty
    );
  });
}

/**
 * Clear sensitive data from memory (best effort)
 */
export function clearSensitiveData(obj: any): void {
  try {
    if (typeof obj === "string") {
      // JavaScript strings are immutable, but we can try to overwrite the reference
      obj = "";
    } else if (Buffer.isBuffer(obj)) {
      // Fill buffer with zeros
      obj.fill(0);
    } else if (obj instanceof Uint8Array) {
      // Clear typed arrays
      obj.fill(0);
    } else if (typeof obj === "object" && obj !== null) {
      // Clear object properties
      Object.keys(obj).forEach((key) => {
        if (obj.hasOwnProperty(key)) {
          clearSensitiveData(obj[key]);
          delete obj[key];
        }
      });
    }
  } catch (error) {
    // Ignore errors during cleanup
    console.warn("Warning: Could not clear sensitive data from memory");
  }
}

/**
 * Sanitize file path for security
 */
export function sanitizePath(filePath: string): string {
  // Remove dangerous path traversal attempts
  return filePath.replace(/\.\./g, "").replace(/[<>:"|?*]/g, "");
}

/**
 * Generate a secure random string
 */
export function generateRandomString(length: number = 32): string {
  return crypto.randomBytes(length).toString("hex");
}

/**
 * Secure memory allocation for sensitive data
 */
export function secureBuffer(size: number): Buffer {
  const buffer = Buffer.alloc(size);
  // Fill with random data first
  crypto.randomFillSync(buffer);
  return buffer;
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Get file size in human readable format
 */
export function formatFileSize(bytes: number): string {
  const sizes = ["Bytes", "KB", "MB", "GB"];
  if (bytes === 0) return "0 Bytes";

  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round((bytes / Math.pow(1024, i)) * 100) / 100 + " " + sizes[i];
}
