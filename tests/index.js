import { validateFile } from "../index.js";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const runTests = async () => {
  const testFiles = [
    path.join(__dirname, "./assets/doc-sample.pdf"),
    path.join(__dirname, "./assets/doc-sample-injected.pdf"),
    path.join(__dirname, "./assets/image-sample.jpg"),
    path.join(__dirname, "./assets/image-sample-injected.jpg"),
    path.join(__dirname, "./assets/icon-sample-injected.svg"),
    path.join(__dirname, "./assets/icon-sample.svg"),
  ];

  console.log("\nRunning file validation tests...\n");

  for (const file of testFiles) {
    try {
      console.log(`Testing file: ${file}`);
      const result = await validateFile(file);
      console.log(`Result: ${result.status ? "✅" : "❌"} ${result.message}\n`);
    } catch (error) {
      console.log(`Error testing ${file}: ${error.message}\n`);
    }
  }
};

runTests().catch((error) => {
  console.error("Test execution failed:", error);
});
