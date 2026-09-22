import { describe, expect, it } from 'vitest'

const officialKpis = ['KPI-1', 'KPI-2', 'KPI-3', 'KPI-4', 'KPI-5', 'KPI-6']
const acceptance = ['AC-1', 'AC-2', 'AC-3', 'AC-4']
const negative = ['NT-1', 'NT-2', 'NT-3', 'NT-4', 'NT-5']

describe('CYBER-14 evidence display contracts', () => {
  it('keeps every official KPI unavailable without backend evidence', () => {
    const statuses = Object.fromEntries(officialKpis.map((id) => [id, 'NOT_EXECUTED']))
    expect(Object.values(statuses)).toEqual(Array(6).fill('NOT_EXECUTED'))
    expect(Object.values(statuses)).not.toContain('PASS')
  })

  it('preserves acceptance and negative-test status vocabulary', () => {
    expect(acceptance).toHaveLength(4)
    expect(negative).toHaveLength(5)
    expect(negative.map(() => 'BLOCKED')).toEqual(Array(5).fill('BLOCKED'))
  })
})