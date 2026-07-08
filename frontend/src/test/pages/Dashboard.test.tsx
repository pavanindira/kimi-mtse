import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import Dashboard from '../../pages/Dashboard';

const mockUseDashboardTrends = vi.fn();

vi.mock('../../lib/hooks', () => ({
  useEngagements: () => ({ data: [] }),
  useFindings: () => ({ data: { items: [], total: 0 } }),
  useDashboardTrends: (days: number) => mockUseDashboardTrends(days),
}));

vi.mock('../../lib/auth-context', () => ({
  useAuth: () => ({ user: { id: 1, username: 'analyst', role: 'Analyst' } }),
}));

function renderDashboard() {
  return render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>,
  );
}

const emptyTrends = {
  days: 90,
  findings_by_week: [],
  scans_by_week: [],
  open_severity_snapshot: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
  resolved_count: 0,
  avg_days_to_resolve: null,
};

const populatedTrends = {
  days: 90,
  findings_by_week: [
    { week_start: '2026-06-01', Critical: 2, High: 1, Medium: 0, Low: 0, Info: 0 },
    { week_start: '2026-06-08', Critical: 0, High: 3, Medium: 1, Low: 0, Info: 0 },
  ],
  scans_by_week: [
    { week_start: '2026-06-01', total: 5, completed: 4, failed: 1 },
  ],
  open_severity_snapshot: { Critical: 2, High: 4, Medium: 1, Low: 0, Info: 0 },
  resolved_count: 3,
  avg_days_to_resolve: 4.5,
};

describe('Dashboard trends', () => {
  beforeEach(() => {
    mockUseDashboardTrends.mockReset();
  });

  it('shows empty-state messaging when there is no trend data', () => {
    mockUseDashboardTrends.mockReturnValue({ data: emptyTrends, isLoading: false });
    renderDashboard();
    expect(screen.getByText('No findings discovered in this period.')).toBeInTheDocument();
    expect(screen.getByText('No scans run in this period.')).toBeInTheDocument();
  });

  it('shows a loading state while trends are fetching', () => {
    mockUseDashboardTrends.mockReturnValue({ data: undefined, isLoading: true });
    renderDashboard();
    expect(screen.getAllByText('Loading…').length).toBeGreaterThan(0);
  });

  it('renders resolution stats when present', () => {
    mockUseDashboardTrends.mockReturnValue({ data: populatedTrends, isLoading: false });
    renderDashboard();
    expect(screen.getByText('4.5')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('shows an em dash for avg resolve time when nothing has been resolved', () => {
    mockUseDashboardTrends.mockReturnValue({ data: emptyTrends, isLoading: false });
    renderDashboard();
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('defaults to the 90-day period and switching period re-queries with new days', async () => {
    mockUseDashboardTrends.mockReturnValue({ data: populatedTrends, isLoading: false });
    const user = userEvent.setup();
    renderDashboard();

    expect(mockUseDashboardTrends).toHaveBeenCalledWith(90);

    await user.click(screen.getByRole('button', { name: '30d' }));
    await waitFor(() => {
      expect(mockUseDashboardTrends).toHaveBeenCalledWith(30);
    });
  });

  it('renders severity legend entries for the findings trend chart', () => {
    mockUseDashboardTrends.mockReturnValue({ data: populatedTrends, isLoading: false });
    renderDashboard();
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();
  });
});
