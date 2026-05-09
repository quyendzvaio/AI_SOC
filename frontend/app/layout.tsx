import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI-SOC Dashboard",
  description: "Realtime AI-SOC monitoring dashboard",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="vi">
      <body>{children}</body>
    </html>
  );
}
