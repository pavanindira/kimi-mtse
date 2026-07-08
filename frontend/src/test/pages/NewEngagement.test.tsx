import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import NewEngagement from '../../pages/NewEngagement';

const mockMutateAsync = vi.fn();
const mockNavigate = vi.fn();

vi.mock('../../lib/hooks', () => ({
  useCreateEngagement: () => ({ mutateAsync: mockMutateAsync, isPending: false }),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

function renderPage() {
  return render(
    <MemoryRouter>
      <NewEngagement />
    </MemoryRouter>,
  );
}

async function fillRequired(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByPlaceholderText('Web Application Penetration Test'), 'Test Engagement');
  await user.type(screen.getByPlaceholderText('Acme Corp'), 'Acme Corp');
}

describe('NewEngagement', () => {
  beforeEach(() => {
    mockMutateAsync.mockReset();
    mockNavigate.mockReset();
  });

  it('requires an engagement name before submitting', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByPlaceholderText('Acme Corp'), 'Acme Corp');
    await user.click(screen.getByRole('button', { name: /create engagement/i }));

    expect(await screen.findByText('Engagement name is required')).toBeInTheDocument();
    expect(mockMutateAsync).not.toHaveBeenCalled();
  });

  it('requires a client name before submitting', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByPlaceholderText('Web Application Penetration Test'), 'Test Engagement');
    await user.click(screen.getByRole('button', { name: /create engagement/i }));

    expect(await screen.findByText('Client name is required')).toBeInTheDocument();
    expect(mockMutateAsync).not.toHaveBeenCalled();
  });

  it.each(['ftp://hooks.example.com', 'hooks.example.com', 'javascript:alert(1)'])(
    'rejects a webhook URL without an http(s) scheme: %s',
    async (badUrl) => {
      const user = userEvent.setup();
      renderPage();
      await fillRequired(user);
      await user.type(screen.getByPlaceholderText('https://hooks.example.com/mste'), badUrl);
      await user.click(screen.getByRole('button', { name: /create engagement/i }));

      expect(await screen.findByText('Webhook URL must start with http:// or https://'))
        .toBeInTheDocument();
      expect(mockMutateAsync).not.toHaveBeenCalled();
    },
  );

  it('accepts a valid https webhook URL and submits successfully', async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: 42 });
    const user = userEvent.setup();
    renderPage();
    await fillRequired(user);
    await user.type(screen.getByPlaceholderText('https://hooks.example.com/mste'),
                    'https://hooks.example.com/mste');
    await user.click(screen.getByRole('button', { name: /create engagement/i }));

    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalledWith(expect.objectContaining({
        name: 'Test Engagement',
        client_name: 'Acme Corp',
        webhook_url: 'https://hooks.example.com/mste',
      }));
    });
    expect(mockNavigate).toHaveBeenCalledWith('/engagements/42');
  });

  it('omits empty optional fields rather than sending blank strings', async () => {
    mockMutateAsync.mockResolvedValueOnce({ id: 7 });
    const user = userEvent.setup();
    renderPage();
    await fillRequired(user);
    await user.click(screen.getByRole('button', { name: /create engagement/i }));

    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalledWith({
        name: 'Test Engagement',
        client_name: 'Acme Corp',
        description: undefined,
        scope: undefined,
        webhook_url: undefined,
      });
    });
  });

  it('shows the API error message and does not navigate when creation fails', async () => {
    mockMutateAsync.mockRejectedValueOnce(new Error('Server exploded'));
    const user = userEvent.setup();
    renderPage();
    await fillRequired(user);
    await user.click(screen.getByRole('button', { name: /create engagement/i }));

    expect(await screen.findByText('Server exploded')).toBeInTheDocument();
    expect(mockNavigate).not.toHaveBeenCalled();
  });
});
