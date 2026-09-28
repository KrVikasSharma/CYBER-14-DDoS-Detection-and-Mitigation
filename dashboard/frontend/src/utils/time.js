/**
 * CYBER-14 Timezone & Timestamp Utility
 * Strategy:
 *  - Database & Backend: UTC (with 'Z' suffix)
 *  - Frontend Dashboard: Asia/Kolkata (IST: UTC+05:30)
 */

export const IST_TIMEZONE = 'Asia/Kolkata'

/**
 * Robustly parses any ISO-8601 string, MySQL datetime string, or Date object into a JavaScript Date.
 * If the string has no timezone indicator, it explicitly treats it as UTC ('Z') so browsers do
 * not misinterpret backend database timestamps as local naive time.
 *
 * @param {string|number|Date|null|undefined} value
 * @returns {Date|null}
 */
export function parseUTC(value) {
  if (!value) return null
  if (value instanceof Date) return isNaN(value.getTime()) ? null : value
  let str = String(value).trim()
  if (!str || str === 'null' || str === 'undefined') return null

  // Replace SQL space format 'YYYY-MM-DD HH:MM:SS' with 'T'
  if (str.includes(' ') && !str.includes('T')) {
    str = str.replace(' ', 'T')
  }

  // If no timezone offset (+/-HH:MM or Z) is present, append 'Z' to treat as UTC
  if (!str.endsWith('Z') && !str.endsWith('z') && !str.match(/[+-]\d{2}:?\d{2}$/)) {
    str += 'Z'
  }

  const d = new Date(str)
  return isNaN(d.getTime()) ? null : d
}

/**
 * Format a timestamp as time-only in Asia/Kolkata (IST).
 * Example: '08:21:45 am'
 *
 * @param {string|Date|null|undefined} value
 * @returns {string}
 */
export function formatTimeIST(value) {
  const d = parseUTC(value)
  if (!d) return 'N/A'
  return d.toLocaleTimeString('en-IN', {
    timeZone: IST_TIMEZONE,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  })
}

/**
 * Format a timestamp as date-only in Asia/Kolkata (IST).
 * Example: '22 Sept 2026'
 *
 * @param {string|Date|null|undefined} value
 * @returns {string}
 */
export function formatDateIST(value) {
  const d = parseUTC(value)
  if (!d) return 'N/A'
  return d.toLocaleDateString('en-IN', {
    timeZone: IST_TIMEZONE,
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  })
}

/**
 * Format a timestamp as complete date & time in Asia/Kolkata (IST).
 * Example: '22 Sept 2026, 08:21:45 am IST'
 *
 * @param {string|Date|null|undefined} value
 * @returns {string}
 */
export function formatDateTimeIST(value) {
  const d = parseUTC(value)
  if (!d) return 'N/A'
  return (
    d.toLocaleString('en-IN', {
      timeZone: IST_TIMEZONE,
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    }) + ' IST'
  )
}

