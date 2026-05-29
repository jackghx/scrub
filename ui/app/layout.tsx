import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Scrub, review before export",
  description:
    "Local-first security-artefact sanitiser. Review what was detected and decide " +
    "what to scrub before you share. The data never leaves your machine.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
