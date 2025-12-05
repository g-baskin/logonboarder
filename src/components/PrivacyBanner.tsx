'use client';

import { useCallback, useEffect, useState } from 'react';
import { Shield, X } from 'lucide-react';

/**
 * Privacy Banner Component
 *
 * Displays a privacy notice to first-time visitors reassuring them that:
 * - No data is logged or stored
 * - All analysis happens locally
 * - Their data remains private
 *
 * Auto-dismisses after 15 seconds or can be manually closed.
 * Uses localStorage to track if user has seen the banner.
 */
export function PrivacyBanner() {
  const [isVisible, setIsVisible] = useState(false);
  const [isAnimatingOut, setIsAnimatingOut] = useState(false);

  const handleDismiss = useCallback(() => {
    setIsAnimatingOut(true);

    // Wait for animation to complete before hiding
    setTimeout(() => {
      setIsVisible(false);
      localStorage.setItem('privacy-banner-seen', 'true');
    }, 300);
  }, []);

  useEffect(() => {
    // TEMPORARY: Always show banner for testing
    // TODO: Re-enable localStorage check after testing
    // const hasSeenBanner = localStorage.getItem('privacy-banner-seen');
    // if (!hasSeenBanner) {

    // Show banner after a brief delay for better UX
    setTimeout(() => setIsVisible(true), 500);

    // Auto-dismiss after 15 seconds
    const timer = setTimeout(() => {
      handleDismiss();
    }, 15000);

    return () => clearTimeout(timer);
  }, [handleDismiss]);

  if (!isVisible) return null;

  return (
    <div
      className={`
        fixed top-0 left-0 right-0 z-50
        bg-gradient-to-r from-green-50 to-blue-50
        dark:from-green-950 dark:to-blue-950
        border-b-2 border-green-500 dark:border-green-700
        shadow-lg
        transition-all duration-300 ease-in-out
        ${isAnimatingOut ? 'translate-y-[-100%] opacity-0' : 'translate-y-0 opacity-100'}
      `}
      role="alert"
      aria-live="polite"
    >
      <div className="container mx-auto px-4 py-3">
        <div className="flex items-center justify-between gap-4">
          {/* Icon and Message */}
          <div className="flex items-start gap-3 flex-1">
            <div className="flex-shrink-0 mt-0.5">
              <Shield className="w-6 h-6 text-green-600 dark:text-green-400" aria-hidden="true" />
            </div>

            <div className="flex-1">
              <h3 className="font-semibold text-sm text-green-900 dark:text-green-100 mb-1">
                🔒 Your Privacy is Protected
              </h3>
              <p className="text-xs text-green-800 dark:text-green-200 leading-relaxed">
                <strong>Zero Data Collection:</strong> We do not log, store, or transmit your data.
                All log analysis happens locally in your browser. Your paths, log samples, and
                configurations are <strong>never sent to our servers</strong> and remain completely
                private. Your data stays yours.
              </p>
            </div>
          </div>

          {/* Dismiss Button */}
          <button
            onClick={handleDismiss}
            className="
              flex-shrink-0
              p-1.5
              rounded-md
              hover:bg-green-200 dark:hover:bg-green-800
              transition-colors
              focus:outline-none
              focus:ring-2
              focus:ring-green-500
              focus:ring-offset-2
            "
            aria-label="Dismiss privacy notice"
          >
            <X className="w-5 h-5 text-green-700 dark:text-green-300" />
          </button>
        </div>
      </div>

      {/* Progress bar for auto-dismiss */}
      <div
        className="h-1 bg-green-500 dark:bg-green-600 animate-shrink"
        style={{ animation: 'shrink 15s linear forwards' }}
      />
    </div>
  );
}
