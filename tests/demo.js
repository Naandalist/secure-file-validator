import { validateFile } from 'secure-file-validator';
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * This demo shows how the PDF whitelist feature solves the false positive issue
 * described in GitHub issue #1
 */
const runDemo = async () => {
  console.log("\n" + "=".repeat(70));
  console.log("PDF Whitelist Feature Demo");
  console.log("Solving False Positive Issues (GitHub Issue #1)");
  console.log("=".repeat(70) + "\n");

  const testFile = path.join(__dirname, "./assets/eicar-adobe-acrobat-javascript-alert.pdf");

  console.log("📄 Testing file: eicar-adobe-acrobat-javascript-alert.pdf\n");

  // Scenario 1: Default behavior (strict security)
  console.log("Scenario 1: Default Validation (Strict Security)");
  console.log("-".repeat(50));
  try {
    const result = await validateFile(testFile);
    console.log(`Status: ${result.status ? "✅ PASS" : "❌ FAIL"}`);
    console.log(`Message: ${result.message}`);
    console.log("⚠️  Issue: Legitimate PDFs with metadata might be rejected!\n");
  } catch (error) {
    console.log(`Error: ${error.message}\n`);
  }

  // Scenario 2: With Metadata whitelisted (common use case)
  console.log("Scenario 2: With Metadata Whitelisted");
  console.log("-".repeat(50));
  console.log("Code: validateFile(path, { pdfWhitelist: ['Metadata'] })");
  try {
    const result = await validateFile(testFile, { 
      pdfWhitelist: ['Metadata'] 
    });
    console.log(`Status: ${result.status ? "✅ PASS" : "❌ FAIL"}`);
    console.log(`Message: ${result.message}`);
    console.log("✅ Solution: Metadata is now allowed, legitimate PDFs pass!\n");
  } catch (error) {
    console.log(`Error: ${error.message}\n`);
  }

  // Scenario 3: Multiple patterns whitelisted
  console.log("Scenario 3: Multiple Patterns Whitelisted");
  console.log("-".repeat(50));
  console.log("Code: validateFile(path, { pdfWhitelist: ['Metadata', 'OpenAction', 'JS'] })");
  try {
    const result = await validateFile(testFile, { 
      pdfWhitelist: ['Metadata', 'OpenAction', 'JS'] 
    });
    console.log(`Status: ${result.status ? "✅ PASS" : "❌ FAIL"}`);
    console.log(`Message: ${result.message}`);
    console.log("✅ Flexibility: Users can whitelist multiple common patterns\n");
  } catch (error) {
    console.log(`Error: ${error.message}\n`);
  }

  // Testing a legitimate PDF
  console.log("=".repeat(70));
  const legitimateFile = path.join(__dirname, "./assets/doc-sample.pdf");
  console.log("📄 Testing file: doc-sample.pdf (Legitimate PDF)\n");

  console.log("Scenario 4: Legitimate PDF - No Whitelist Needed");
  console.log("-".repeat(50));
  try {
    const result = await validateFile(legitimateFile);
    console.log(`Status: ${result.status ? "✅ PASS" : "❌ FAIL"}`);
    console.log(`Message: ${result.message}`);
    console.log("✅ Backward Compatibility: Clean PDFs still pass without changes\n");
  } catch (error) {
    console.log(`Error: ${error.message}\n`);
  }

  console.log("=".repeat(70));
  console.log("\n💡 Key Benefits:");
  console.log("   • Solves false positive issues from GitHub issue #1");
  console.log("   • Fully backward compatible - no breaking changes");
  console.log("   • Flexible - users can whitelist only what they need");
  console.log("   • Secure by default - strict validation without whitelist");
  console.log("   • Well documented - clear examples and API reference\n");
};

runDemo().catch((error) => {
  console.error("Demo failed:", error);
});
