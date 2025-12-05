import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import { TRPCProvider } from '@/trpc/client';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import './globals.css';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  title: 'LogOnboard-AI',
  description: 'Intelligent SIEM configuration generator powered by AI-driven log analysis',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
        <ErrorBoundary>
          <TRPCProvider>{children}</TRPCProvider>
        </ErrorBoundary>
      </body>
    </html>
  );
}
