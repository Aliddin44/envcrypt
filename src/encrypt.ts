import fs from "fs";
import readline from "readline";
import { encrypt } from "./utils.js";
import { createCipheriv, randomBytes, scrypt, pbkdf2 } from "crypto";
import { readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { promisify } from "util";
import { getPassword, validateEnvFile, clearSensitiveData } from "./utils.js";
import chalk from "chalk";

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
  version: string;
}

function promptPassword(): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout }) as readline.Interface & { stdoutMuted?: boolean };
    rl.stdoutMuted = true;

    rl.question("🔐 Enter password: ", (password) => {
      rl.close();
      console.log();
      resolve(password);
    });

    (rl as any)._writeToOutput = function _writeToOutput(stringToWrite: string) {
      if (rl.stdoutMuted) (rl as any)._output.write("*");
      else (rl as any)._output.write(stringToWrite);
    };
  });
}

export async function encryptFile(
  inputPath: string,
  outputPath: string,
  password: string | null,
  algorithm: "argon2" | "scrypt" = "argon2",
  force: boolean = false
): Promise<void> {
  let key: Buffer | null = null;
  let encryptionPassword: string | null = null;

  try {
    // Check if input file exists
    if (!existsSync(inputPath)) {
      throw new Error(`Input file not found: ${inputPath}`);
    }

    // Check if output file exists
    if (!force && existsSync(outputPath)) {
      throw new Error(`Output file already exists: ${outputPath}. Use --force to overwrite`);
    }

    // Get password securely
    encryptionPassword = password || (await getPassword("Enter encryption password: "));

    if (!encryptionPassword || encryptionPassword.length < 6) {
      throw new Error("Password must be at least 6 characters long");
    }

    // Read and validate file content
    const envContent = await readFile(inputPath, "utf8");

    if (!envContent.trim()) {
      throw new Error("ENV file is empty or does not exist");
    }

    if (!validateEnvFile(envContent)) {
      console.warn(chalk.yellow("⚠️  Warning: File does not appear to be a valid .env file"));
    }

    // Generate cryptographic materials
    const salt = randomBytes(32);
    const iv = randomBytes(16);

    // Derive encryption key
    try {
      if (algorithm === "scrypt") {
        key = (await scryptAsync(encryptionPassword, salt, 32)) as Buffer;
      } else if (algorithm === "argon2") {
        // For argon2, we'll use pbkdf2 as fallback since argon2 requires additional dependency
        // In production, you should use actual argon2 library
        key = (await pbkdf2Async(encryptionPassword, salt, 100000, 32, "sha512")) as Buffer;
      } else {
        // Default to pbkdf2
        key = (await pbkdf2Async(encryptionPassword, salt, 100000, 32, "sha512")) as Buffer;
      }
    } catch (keyError: any) {
      throw new Error(`Failed to derive encryption key: ${keyError.message}`);
    }

    // Encrypt the content
    let encrypted: string;
    let authTag: string | undefined;

    try {
      // Use AES-256-GCM for authenticated encryption
      const cipher = createCipheriv("aes-256-gcm", key, iv);

      encrypted = cipher.update(envContent, "utf8", "hex");
      encrypted += cipher.final("hex");

      // Get authentication tag for GCM mode
      authTag = cipher.getAuthTag().toString("hex");
    } catch (encryptError: any) {
      throw new Error(`Encryption failed: ${encryptError.message}`);
    }

    // Prepare encrypted data structure
    const encryptedData: EncryptedData = {
      algorithm: "aes-256-gcm",
      keyDerivation: algorithm === "scrypt" ? "scrypt" : "pbkdf2",
      salt: salt.toString("hex"),
      iv: iv.toString("hex"),
      data: encrypted,
      authTag: authTag,
      timestamp: Date.now(),
      version: "1.0.0",
    };

    // Save encrypted data
    const jsonOutput = JSON.stringify(encryptedData, null, 2);
    await writeFile(outputPath, jsonOutput, "utf8");

    // Verify the encrypted file was written correctly
    if (!existsSync(outputPath)) {
      throw new Error("Failed to write encrypted file");
    }

    console.log(chalk.green(`✅ File encrypted successfully`));
    console.log(chalk.cyan(`📊 Original size: ${envContent.length} bytes`));
    console.log(chalk.cyan(`📊 Encrypted size: ${jsonOutput.length} bytes`));
    console.log(chalk.cyan(`🔐 Algorithm: ${encryptedData.algorithm}`));
    console.log(chalk.cyan(`🔑 Key derivation: ${encryptedData.keyDerivation}`));
  } catch (error: any) {
    // Clean up sensitive data from memory
    if (key) clearSensitiveData(key);
    if (encryptionPassword) clearSensitiveData(encryptionPassword);

    if (error.code === "ENOENT") {
      throw new Error(`File not found: ${inputPath}`);
    } else if (error.code === "EACCES") {
      throw new Error(`Permission denied: ${error.path}`);
    } else if (error.code === "ENOSPC") {
      throw new Error(`No space left on device`);
    }

    throw new Error(`Encryption error: ${error.message}`);
  } finally {
    // Always clean up sensitive data
    if (key) clearSensitiveData(key);
    if (encryptionPassword) clearSensitiveData(encryptionPassword);
  }
}

/**
 * Encrypt a string directly (utility function)
 */
export async function encryptString(content: string, password: string, algorithm: "argon2" | "scrypt" = "argon2"): Promise<EncryptedData> {
  const salt = randomBytes(32);
  const iv = randomBytes(16);

  let key: Buffer;
  if (algorithm === "scrypt") {
    key = (await scryptAsync(password, salt, 32)) as Buffer;
  } else {
    key = (await pbkdf2Async(password, salt, 100000, 32, "sha512")) as Buffer;
  }

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(content, "utf8", "hex");
  encrypted += cipher.final("hex");

  const authTag = cipher.getAuthTag().toString("hex");

  // Clear sensitive data
  clearSensitiveData(key);

  return {
    algorithm: "aes-256-gcm",
    keyDerivation: algorithm === "scrypt" ? "scrypt" : "pbkdf2",
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    data: encrypted,
    authTag: authTag,
    timestamp: Date.now(),
    version: "1.0.0",
  };
}

/**
 * Get file encryption info without decrypting
 */
export async function getEncryptionInfo(filePath: string): Promise<Partial<EncryptedData>> {
  try {
    const content = await readFile(filePath, "utf8");
    const data = JSON.parse(content);

    // Return non-sensitive information only
    return {
      algorithm: data.algorithm,
      keyDerivation: data.keyDerivation,
      timestamp: data.timestamp,
      version: data.version,
    };
  } catch (error: any) {
    throw new Error(`Cannot read encryption info: ${error.message}`);
  }
}
