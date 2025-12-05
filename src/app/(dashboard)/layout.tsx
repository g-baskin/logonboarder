import Link from 'next/link';
import { PrivacyBanner } from '@/components/PrivacyBanner';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <PrivacyBanner />
      <header className="border-b">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <svg
              className="w-8 h-8 text-primary"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
            <span className="text-xl font-bold">LogOnboard-AI</span>
          </div>
          <nav className="flex items-center gap-4">
            <Link href="/analyze" className="text-sm hover:text-primary">
              Analyze
            </Link>
            <Link href="/ta-translator" className="text-sm hover:text-primary">
              TA Translator
            </Link>
            <Link href="/" className="text-sm hover:text-primary">
              Home
            </Link>
          </nav>
        </div>
      </header>
      <main>{children}</main>
    </div>
  );
}
