import { test, expect } from "@playwright/test";

test.describe("P2P Send Page", () => {
  test("p2p-send page loads with file input", async ({ page }) => {
    await page.goto("http://localhost:5000/static/p2p-send.html");
    
    // Check page title/heading
    await expect(page.locator("h1")).toContainText(/P2P|Send|Transfer/i);
    
    // Check for file input
    const fileInput = page.locator('input[type="file"]');
    await expect(fileInput).toBeVisible();
  });

  test("p2p-send page uploads file and shows magnet link", async ({ page }) => {
    await page.goto("http://localhost:5000/static/p2p-send.html");
    
    // Create a test file
    const testContent = Buffer.from("Test file content for P2P transfer");
    
    // Upload file
    await page.setInputFiles('input[type="file"]', {
      name: "test-file.txt",
      mimeType: "text/plain",
      buffer: testContent,
    });
    
    // Click submit/upload button
    await page.click('button[type="submit"], button:has-text("Upload"), button:has-text("Send")');
    
    // Wait for processing
    await page.waitForSelector("#magnet-link, .magnet-link", { timeout: 10000 });
    
    // Verify magnet link is displayed
    const magnetLink = page.locator("#magnet-link, .magnet-link");
    await expect(magnetLink).toBeVisible();
    const magnetText = await magnetLink.textContent();
    expect(magnetText).toContain("magnet:?");
    
    // Verify PIN is displayed
    const pin = page.locator("#pin, .pin");
    await expect(pin).toBeVisible();
    const pinText = await pin.textContent();
    expect(pinText).toMatch(/\d{6}/);
  });

  test("p2p-send page allows sending email with transfer link", async ({ page }) => {
    await page.goto("http://localhost:5000/static/p2p-send.html");
    
    // Upload a file first
    const testContent = Buffer.from("Test file for email");
    await page.setInputFiles('input[type="file"]', {
      name: "email-test.txt",
      mimeType: "text/plain",
      buffer: testContent,
    });
    
    await page.click('button[type="submit"], button:has-text("Upload"), button:has-text("Send")');
    await page.waitForSelector("#email-input, input[type=\"email\"]", { timeout: 10000 });
    
    // Fill in email
    await page.fill("#email-input, input[type=\"email\"]", "recipient@example.com");
    
    // Click send email button
    await page.click('button:has-text("Send Email"), button:has-text("Email Link")');
    
    // Verify success message
    await expect(page.locator(".success-message, .email-sent")).toBeVisible({ timeout: 5000 });
  });
});
