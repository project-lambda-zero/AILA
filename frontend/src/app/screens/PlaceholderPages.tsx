/**
 * Placeholder pages for routes that will be fully implemented in later plans.
 * Plan 03 will replace SessionsPlaceholder with the real session management page.
 */

function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-64 gap-4 text-center">
      <p className="font-mono text-lg font-bold text-accent tracking-widest">{title}</p>
      <p className="text-text-muted text-sm">Coming soon</p>
    </div>
  );
}

export function SettingsPlaceholder() {
  return <PlaceholderPage title="SETTINGS" />;
}

export function SessionsPlaceholder() {
  return <PlaceholderPage title="SESSIONS" />;
}
