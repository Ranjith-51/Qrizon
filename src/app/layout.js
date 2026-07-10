import "./globals.css";

export const metadata = {
  title: "QRizon — Malicious QR Code Detection",
  description: "Scan and analyze QR codes for phishing and security risks before you tap.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
