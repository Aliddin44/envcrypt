import fs from "fs";
import readline from "readline";
import { decryptFile } from "./decrypt.js";
import { unlinkSync, mkdtempSync } from "fs";
import { readFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

function promptPassword(): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    (rl as any).stdoutMuted = true;

    rl.question("🔐 Enter password: ", (password) => {
      rl.close();
      console.log();
      resolve(password);
    });

    (rl as any)._writeToOutput = function _writeToOutput(stringToWrite: string) {
      if ((rl as any).stdoutMuted) (rl as any).output.write("*");
      else (rl as any).output.write(stringToWrite);
    };
  });
}

export async function loadEncryptedEnv(inputPath: string, password: string | null): Promise<number> {
  if (!password) password = await promptPassword();
  // Vaqtinchalik fayl yaratish
  const tempDir = mkdtempSync(join(tmpdir(), "envcrypt-"));
  const tempFile = join(tempDir, ".env.temp");

  try {
    // Faylni vaqtinchalik joyga deshifrlash
    await decryptFile(inputPath, tempFile, password, true);

    // Deshifrlangan faylni o'qish
    const envContent = readFileSync(tempFile, "utf8");

    // ENV o'zgaruvchilarini parse qilish va process.env ga yuklash
    let loadedCount = 0;

    envContent.split("\n").forEach((line) => {
      const trimmed = line.trim();

      // Bo'sh qatorlar va izohlarni o'tkazib yuborish
      if (!trimmed || trimmed.startsWith("#")) {
        return;
      }

      // KEY=VALUE formatini parse qilish
      const equalIndex = trimmed.indexOf("=");
      if (equalIndex === -1) {
        return;
      }

      const key = trimmed.substring(0, equalIndex).trim();
      const value = trimmed.substring(equalIndex + 1).trim();

      // Qo'shtirnoqlarni olib tashlash
      const cleanValue = value.replace(/^["']|["']$/g, "");

      if (key) {
        process.env[key] = cleanValue;
        loadedCount++;
      }
    });

    return loadedCount;
  } finally {
    // Vaqtinchalik faylni o'chirish
    try {
      unlinkSync(tempFile);
    } catch (error) {
      // Ahamiyatsiz xato
    }
  }
}
