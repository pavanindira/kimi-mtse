import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { CvssBadge, SevBadge, StatusBadge } from '../../components/Badges';

describe('SevBadge', () => {
  it('renders the severity label', () => {
    render(<SevBadge severity="Critical" />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });

  it('falls back gracefully for an unknown severity rather than crashing', () => {
    render(<SevBadge severity="Unknown" />);
    expect(screen.getByText('Unknown')).toBeInTheDocument();
  });
});

describe('StatusBadge', () => {
  it('renders the status label', () => {
    render(<StatusBadge status="Completed" />);
    expect(screen.getByText('Completed')).toBeInTheDocument();
  });

  it('applies a pulse animation only while Running', () => {
    const { container: running } = render(<StatusBadge status="Running" />);
    expect(running.querySelector('span')).toHaveStyle({
      animation: 'pulse 1.6s ease-in-out infinite',
    });

    const { container: completed } = render(<StatusBadge status="Completed" />);
    expect(completed.querySelector('span')?.style.animation).toBeFalsy();
  });
});

describe('CvssBadge', () => {
  it('renders an em dash when score is null', () => {
    render(<CvssBadge score={null} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('renders the score to one decimal place', () => {
    render(<CvssBadge score={9.8} />);
    expect(screen.getByText('9.8')).toBeInTheDocument();
  });

  it('rounds to one decimal place for scores with more precision', () => {
    render(<CvssBadge score={7.256} />);
    expect(screen.getByText('7.3')).toBeInTheDocument();
  });
});
