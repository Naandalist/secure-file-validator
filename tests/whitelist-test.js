import { validateFile } from '../index.js';
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const runWhitelistTests = async () => {
  console.log("\n🧪 Running PDF whitelist tests...\n");

  const testFile = path.join(__dirname, "./assets/eicar-adobe-acrobat-javascript-alert.pdf");

  // Test 1: Without whitelist - should fail on Metadata
  console.log("Test 1: Validating without whitelist");
  try {
    const result1 = await validateFile(testFile);
    console.log(`Result: ${result1.status ? "✅" : "❌"} ${result1.message}`);
  } catch (error) {
    console.log(`Error: ${error.message}`);
  }

  // Test 2: With Metadata whitelisted - should fail on JavaScript
  console.log("\nTest 2: Validating with Metadata whitelisted");
  try {
    const result2 = await validateFile(testFile, { 
      pdfWhitelist: ['Metadata'] 
    });
    console.log(`Result: ${result2.status ? "✅" : "❌"} ${result2.message}`);
  } catch (error) {
    console.log(`Error: ${error.message}`);
  }

  // Test 3: With both Metadata and JavaScript whitelisted - should fail on other pattern
  console.log("\nTest 3: Validating with Metadata and JavaScript whitelisted");
  try {
    const result3 = await validateFile(testFile, { 
      pdfWhitelist: ['Metadata', 'JavaScript'] 
    });
    console.log(`Result: ${result3.status ? "✅" : "❌"} ${result3.message}`);
  } catch (error) {
    console.log(`Error: ${error.message}`);
  }

  // Test 4: Test with legitimate PDF (doc-sample.pdf) - should pass
  console.log("\nTest 4: Validating legitimate PDF");
  const legitimateFile = path.join(__dirname, "./assets/doc-sample.pdf");
  try {
    const result4 = await validateFile(legitimateFile);
    console.log(`Result: ${result4.status ? "✅" : "❌"} ${result4.message}`);
  } catch (error) {
    console.log(`Error: ${error.message}`);
  }

  // Test 5: Test with legitimate PDF with common patterns whitelisted
  console.log("\nTest 5: Validating legitimate PDF with whitelist");
  try {
    const result5 = await validateFile(legitimateFile, {
      pdfWhitelist: ['Metadata', 'OpenAction', 'JS']
    });
    console.log(`Result: ${result5.status ? "✅" : "❌"} ${result5.message}`);
  } catch (error) {
    console.log(`Error: ${error.message}`);
  }

  console.log("\n✨ Whitelist tests completed!\n");
};

runWhitelistTests().catch((error) => {
  console.error("Test execution failed:", error);
});
