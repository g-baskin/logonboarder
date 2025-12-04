import Link from 'next/link';

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col bg-gradient-to-b from-zinc-900 to-black text-white">
      <header className="container mx-auto px-4 py-6">
        <nav className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <svg
              className="w-8 h-8 text-blue-500"
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
          <Link
            href="/analyze"
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium hover:bg-blue-700 transition-colors"
          >
            Get Started
          </Link>
        </nav>
      </header>

      <main className="flex-1 container mx-auto px-4 py-16">
        <div className="max-w-3xl mx-auto text-center">
          <h1 className="text-5xl font-bold mb-6 bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
            Splunk Onboarding Made Simple
          </h1>
          <p className="text-xl text-zinc-400 mb-8">
            Generate production-ready Splunk configurations from file paths alone. No log samples
            required.
          </p>

          <div className="flex gap-4 justify-center mb-16">
            <Link
              href="/analyze"
              className="rounded-lg bg-blue-600 px-6 py-3 text-lg font-medium hover:bg-blue-700 transition-colors"
            >
              Analyze Paths
            </Link>
            <a
              href="#features"
              className="rounded-lg border border-zinc-700 px-6 py-3 text-lg font-medium hover:bg-zinc-800 transition-colors"
            >
              Learn More
            </a>
          </div>

          <div id="features" className="grid md:grid-cols-3 gap-8 text-left">
            <div className="p-6 rounded-xl bg-zinc-800/50 border border-zinc-700">
              <div className="w-12 h-12 rounded-lg bg-blue-600/20 flex items-center justify-center mb-4">
                <svg
                  className="w-6 h-6 text-blue-500"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M13 10V3L4 14h7v7l9-11h-7z"
                  />
                </svg>
              </div>
              <h3 className="text-lg font-semibold mb-2">Path-Based Analysis</h3>
              <p className="text-zinc-400 text-sm">
                Automatically detect sourcetypes from file paths using our intelligent knowledge
                base.
              </p>
            </div>

            <div className="p-6 rounded-xl bg-zinc-800/50 border border-zinc-700">
              <div className="w-12 h-12 rounded-lg bg-purple-600/20 flex items-center justify-center mb-4">
                <svg
                  className="w-6 h-6 text-purple-500"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                  />
                </svg>
              </div>
              <h3 className="text-lg font-semibold mb-2">Sensitive Data Scan</h3>
              <p className="text-zinc-400 text-sm">
                Detect PII, .gov/.mil domains, and generate masking transforms automatically.
              </p>
            </div>

            <div className="p-6 rounded-xl bg-zinc-800/50 border border-zinc-700">
              <div className="w-12 h-12 rounded-lg bg-green-600/20 flex items-center justify-center mb-4">
                <svg
                  className="w-6 h-6 text-green-500"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                  />
                </svg>
              </div>
              <h3 className="text-lg font-semibold mb-2">Ready-to-Deploy</h3>
              <p className="text-zinc-400 text-sm">
                Download complete configuration bundles with inputs.conf, props.conf, and more.
              </p>
            </div>
          </div>
        </div>
      </main>

      <footer className="container mx-auto px-4 py-8 text-center text-zinc-500 text-sm">
        <p>LogOnboard-AI - Splunk Configuration Generator</p>
      </footer>
    </div>
  );
}
