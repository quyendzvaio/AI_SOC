import { expect, test } from "@playwright/test";

test("dashboard exposes backend SOC capabilities and primary actions are clickable", async ({ page }) => {
  const token = process.env.E2E_AUTH_TOKEN;
  test.skip(!token, "E2E_AUTH_TOKEN is required for authenticated dashboard smoke.");

  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => consoleErrors.push(error.message));

  await page.goto("/");
  await page.evaluate((authToken) => localStorage.setItem("ai_soc_token", authToken), token);
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator("#nav-dashboard")).toBeVisible();

  const grant = page.locator("#btn-grant-device-consent");
  if (await grant.isVisible().catch(() => false)) {
    await grant.click();
  }

  await page.locator("#nav-dashboard").click();
  await expect(page.getByText("Live log/email stream")).toBeVisible();

  await page.locator("#nav-logs").click();
  await expect(page.getByRole("heading", { name: "Logs", exact: true })).toBeVisible();

  await page.locator("#nav-alerts").click();
  await expect(page.getByText("Knowledge search")).toBeVisible();
  await expect(page.getByText("Alerts triage & feedback")).toBeVisible();
  await page.locator('input[placeholder="MITRE, CVE, phishing..."]').fill("brute force T1110");
  await page.getByRole("button", { name: "Tìm" }).click();
  await expect(page.getByText(/score/i).first()).toBeVisible();

  const triage = page.getByRole("button", { name: "Triage" }).first();
  if (await triage.isVisible().catch(() => false)) {
    await triage.click();
    await expect(page.getByText(/Risk/i).first()).toBeVisible();
  }

  await page.locator("#nav-chat").click();
  await page.locator("#chat-input").fill("Tóm tắt alert high gần nhất");
  await expect(page.locator("#btn-send-chat")).toBeEnabled();

  await page.locator("#nav-settings").click();
  await expect(page.getByText("Cloud LLM API")).toBeVisible();
  await expect(page.locator("#btn-save-runtime-config")).toBeVisible();

  expect(consoleErrors).toEqual([]);
});
