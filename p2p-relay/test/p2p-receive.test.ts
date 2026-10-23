import { test, expect } from "@playwright/test";

test.describe("P2P Receive Page", () => {
  test("p2p-receive page loads with PIN input", async ({ page }) => {
    await page.goto("http://localhost:5000/static/p2p-receive.html");
    
    // Check page title/heading
    await expect(page.locator("h1")).toContainText(/P2P|Receive|Download/i);
    
    // Check for PIN input
    const pinInput = page.locator('input[type="text"], input[placeholder*="PIN"]');
    await expect(pinInput).toBeVisible();
  });

  test("p2p-receive page accepts PIN from URL parameter", async ({ page }) => {
    await page.goto("http://localhost:5000/static/p2p-receive.html?pin=123456");
    
    // PIN should be auto-filled
    const pinInput = page.locator('input[type="text"], input[placeholder*="PIN"]');
    const pinValue = await pinInput.inputValue();
    expect(pinValue).toBe("123456");
  });

  test("p2p-receive page shows file info after entering valid PIN", async ({ page }) => {
    // Note: This test requires a mock server or actual backend running
    await page.goto("http://localhost:5000/static/p2p-receive.html");
    
    // Enter PIN
    await page.fill('input[type="text"], input[placeholder*="PIN"]', "123456");
    await page.click('button:has-text("Download"), button:has-text("Continue"), button[type="submit"]');
    
    // Should show file info or error message
    await page.waitForSelector("#filename, .filename, .error-message", { timeout: 5000 });
  });

  test("p2p-receive page has download progress indicator", async ({ page }) => {
    await page.goto("http://localhost:5000/static/p2p-receive.html?pin=123456");
    
    // Progress container should exist (even if hidden initially)
    const progressContainer = page.locator("#progress-container, .progress-container, .progress-bar");
    await expect(progressContainer).toBeAttached();
  });
});
