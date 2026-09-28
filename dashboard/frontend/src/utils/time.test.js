import { describe, expect, it } from 'vitest'
import { formatDateTimeIST, formatDateIST, formatTimeIST, parseUTC } from './time'

describe('CYBER-14 Timezone & Timestamp Utility (Asia/Kolkata)', () => {
  it('correctly parses UTC ISO string with Z suffix', () => {
    const dt = parseUTC('2026-09-22T02:51:45Z')
    expect(dt).toBeInstanceOf(Date)
    expect(dt.getUTCFullYear()).toBe(2026)
    expect(dt.getUTCHours()).toBe(2)
    expect(dt.getUTCMinutes()).toBe(51)
    expect(dt.getUTCSeconds()).toBe(45)
  })

  it('correctly parses ISO string without Z suffix as UTC', () => {
    const dt = parseUTC('2026-09-22T02:51:45')
    expect(dt).toBeInstanceOf(Date)
    expect(dt.getUTCHours()).toBe(2)
    expect(dt.getUTCMinutes()).toBe(51)
  })

  it('correctly parses SQL space-separated datetime string as UTC', () => {
    const dt = parseUTC('2026-09-22 02:51:45')
    expect(dt).toBeInstanceOf(Date)
    expect(dt.getUTCHours()).toBe(2)
    expect(dt.getUTCMinutes()).toBe(51)
  })

  it('converts UTC time to Asia/Kolkata (IST: UTC+05:30) time string', () => {
    // 02:51:45 UTC + 5h30m = 08:21:45 IST
    const timeStr = formatTimeIST('2026-09-22T02:51:45Z')
    expect(timeStr.toLowerCase()).toMatch(/08:21:45/)
    expect(timeStr.toLowerCase()).toMatch(/am/)
  })

  it('converts afternoon UTC time to Asia/Kolkata (IST) time string', () => {
    // 10:00:00 UTC + 5h30m = 15:30:00 IST (03:30:00 pm)
    const timeStr = formatTimeIST('2026-09-22T10:00:00Z')
    expect(timeStr.toLowerCase()).toMatch(/03:30:00/)
    expect(timeStr.toLowerCase()).toMatch(/pm/)
  })

  it('formats full date and time in IST with IST suffix', () => {
    const fullStr = formatDateTimeIST('2026-09-22T02:51:45Z')
    expect(fullStr).toContain('2026')
    expect(fullStr.toLowerCase()).toMatch(/08:21:45/)
    expect(fullStr).toContain('IST')
  })

  it('formats date-only in IST', () => {
    const dateStr = formatDateIST('2026-09-22T02:51:45Z')
    expect(dateStr).toContain('2026')
    expect(dateStr).toMatch(/22/)
  })

  it('gracefully returns N/A for null, undefined, or empty values', () => {
    expect(formatTimeIST(null)).toBe('N/A')
    expect(formatTimeIST(undefined)).toBe('N/A')
    expect(formatTimeIST('')).toBe('N/A')
    expect(formatDateIST(null)).toBe('N/A')
    expect(formatDateTimeIST(null)).toBe('N/A')
    expect(formatDateTimeIST(undefined)).toBe('N/A')
  })
})

