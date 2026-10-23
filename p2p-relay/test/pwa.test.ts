import { test, expect } from "@playwright/test";

test.describe("PWA Features", () => {
  test("manifest.json exists and is valid", async ({ page }) => {
    const response = await page.goto("http://localhost:5000/static/manifest.json");
    expect(response?.status()).toBe(200);
    
    const manifest = await response?.json();
    expect(manifest.name).toBeDefined();
    expect(manifest.short_name).toBeDefined();
    expect(manifest.start_url).toBeDefined();
    expect(manifest.display).toBe("standalone");
    expect(manifest.icons).toBeDefined();
    expect(manifest.icons.length).toBeGreaterThan(0);
  });

  test("manifest includes Web Share Target for Android", async ({ page }) => {
    const response = await page.goto("http://localhost:5000/static/manifest.json");
    const manifest = await response?.json();
    
    expect(manifest.share_target).toBeDefined();
    expect(manifest.share_target.action).toBeDefined();
    expect(manifest.share_target.method).toBe("POST");
    expect(manifest.share_target.params).toBeDefined();
    expect(manifest.share_target.params.files).toBeDefined();
  });

  test("service worker file exists", async ({ page }) => {
    const response = await page.goto("http://localhost:5000/static/sw.js");
    expect(response?.status()).toBe(200);
    
    const content = await response?.text();
    expect(content).toContain("install");
    expect(content).toContain("fetch");
  });

  test("HTML pages link to manifest", async ({ page }) => {
    await page.goto("http://localhost:5000/static/index.html");
    
    const manifestLink = page.locator('link[rel="manifest"]');
    await expect(manifestLink).toBeAttached();
    
    const href = await manifestLink.getAttribute("href");
    expect(href).toContain("manifest.json");
  });

  test("service worker registers successfully", async ({ page }) => {
    await page.goto("http://localhost:5000/static/index.html");
    
    const swRegistered = await page.evaluate(() => {
      return 'serviceWorker' in navigator;
    });
    
    expect(swRegistered).toBe(true);
  });

  test("PWA icons exist", async ({ page }) => {
    // Test 192x192 icon
    const icon192 = await page.goto("http://localhost:5000/static/icons/icon-192.png");
    expect(icon192?.status()).toBe(200);
    
    // Test 512x512 icon
    const icon512 = await page.goto("http://localhost:5000/static/icons/icon-512.png");
    expect(icon512?.status()).toBe(200);
  });
});
