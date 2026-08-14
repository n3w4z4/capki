// Shared style tokens for a single, consistent light theme (indigo accent).
// Keeping these in one place means every page updates together instead of
// six copies of the same Tailwind strings drifting apart.

export const styles = {
  page: 'min-h-screen bg-gray-50',
  card: 'rounded-xl border border-gray-200 bg-white p-6 shadow-sm',
  label: 'block text-sm font-medium text-gray-700',
  input:
    'mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-900 outline-none transition-shadow focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20',
  button:
    'inline-flex items-center justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition-colors hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50',
  buttonSecondary:
    'inline-flex items-center justify-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50',
  link: 'text-sm font-medium text-indigo-600 transition-colors hover:text-indigo-800',
  linkDanger: 'text-sm font-medium text-red-600 transition-colors hover:text-red-800',
  errorBanner: 'rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700',
  warningBanner: 'rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-700',
  successText: 'text-sm font-medium text-green-700',
  sectionTitle: 'text-base font-semibold text-gray-900',
  muted: 'text-sm text-gray-500',
  mutedXs: 'text-xs text-gray-500',
  tableHeadRow: 'border-b border-gray-200 text-left text-xs font-medium uppercase tracking-wide text-gray-500',
  tableRow: 'border-b border-gray-100 last:border-0',
} as const

export type BadgeTone = 'green' | 'red' | 'gray' | 'amber'

const badgeTones: Record<BadgeTone, string> = {
  green: 'bg-green-50 text-green-700 ring-1 ring-inset ring-green-200',
  red: 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-200',
  gray: 'bg-gray-100 text-gray-700 ring-1 ring-inset ring-gray-200',
  amber: 'bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200',
}

export function badgeClass(tone: BadgeTone): string {
  return `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${badgeTones[tone]}`
}
