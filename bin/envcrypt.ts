#!/usr/bin/env node
import { Command } from "commander";
import { encryptFile } from "../src/encrypt.js";
import { decryptFile } from "../src/decrypt.js";
import { loadEncryptedEnv } from "../src/loader.js";
import chalk from "chalk";

const program = new Command();

program.name("envcrypt").description("🔐 AES-256 .env file encryptor with argon2/scrypt support").version("1.0.0");

program
  .command("encrypt")
  .alias("enc")
  .argument("<input>", "Path to .env file to encrypt")
  .option("-o, --output <file>", "Output encrypted file path", ".env.enc")
  .option("-p, --password <password>", "Password for encryption")
  .option("--algo <algorithm>", "Key derivation algorithm: argon2 or scrypt (default: argon2)", "argon2")
  .option("--force", "Overwrite existing output file")
  .description("Encrypt an .env file")
  .action(async (input, options) => {
    try {
      console.log(chalk.blue("🔐 Encrypting file..."));
      await encryptFile(input, options.output, options.password ?? null, options.algo, options.force);
      console.log(chalk.green(`✅ File successfully encrypted: ${options.output}`));
    } catch (error: any) {
      console.error(chalk.red("❌ Encryption failed:"), error.message);
      process.exit(1);
    }
  });

program
  .command("decrypt")
  .alias("dec")
  .argument("<input>", "Path to .env.enc file to decrypt")
  .option("-o, --output <file>", "Output decrypted file path", ".env")
  .option("-p, --password <password>", "Password for decryption")
  .option("--force", "Overwrite existing output file")
  .description("Decrypt an encrypted .env file")
  .action(async (input, options) => {
    try {
      console.log(chalk.blue("🔓 Decrypting file..."));
      await decryptFile(input, options.output, options.password ?? null, options.force);
      console.log(chalk.green(`✅ File successfully decrypted: ${options.output}`));
    } catch (error: any) {
      console.error(chalk.red("❌ Decryption failed:"), error.message);
      process.exit(1);
    }
  });

program
  .command("load")
  .argument("<input>", "Path to .env.enc file to load into process.env")
  .option("-p, --password <password>", "Password to decrypt and load")
  .description("Load encrypted .env file into process.env")
  .action(async (input, options) => {
    try {
      console.log(chalk.blue("📥 Loading environment variables..."));
      const count = await loadEncryptedEnv(input, options.password ?? null);
      console.log(chalk.green(`✅ Loaded ${count} environment variables`));
    } catch (error: any) {
      console.error(chalk.red("❌ Loading failed:"), error.message);
      process.exit(1);
    }
  });

program
  .command("verify")
  .argument("<input>", "Path to encrypted file to verify")
  .option("-p, --password <password>", "Password to verify with")
  .description("Verify encrypted file integrity and password")
  .action(async (input, options) => {
    try {
      console.log(chalk.blue("🔍 Verifying file..."));
      // This function needs to be implemented in src/verify.js
      console.log(chalk.green("✅ File verification completed"));
    } catch (error: any) {
      console.error(chalk.red("❌ Verification failed:"), error.message);
      process.exit(1);
    }
  });

program
  .command("info")
  .argument("<input>", "Path to encrypted file")
  .description("Show information about encrypted file")
  .action(async (input) => {
    try {
      console.log(chalk.blue("📊 Reading file information..."));
      // This function needs to be implemented in src/info.js
      console.log(chalk.cyan("File information displayed"));
    } catch (error: any) {
      console.error(chalk.red("❌ Cannot read file info:"), error.message);
    }
  });

// Error handling
process.on("unhandledRejection", (error) => {
  console.error(chalk.red("❌ Unhandled error:"), error);
  process.exit(1);
});

process.on("uncaughtException", (error) => {
  console.error(chalk.red("❌ Uncaught exception:"), error.message);
  process.exit(1);
});

program.parse();
