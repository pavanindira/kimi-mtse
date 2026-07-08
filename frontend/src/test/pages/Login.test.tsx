import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Login } from '../../pages/Login';

const mockLogin = vi.fn();
const mockNavigate = vi.fn();

vi.mock('../../lib/auth-context', () => ({
  useAuth: () => ({ login: mockLogin, loading: false }),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

function renderLogin() {
  return render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>,
  );
}

describe('Login', () => {
  beforeEach(() => {
    mockLogin.mockReset();
    mockNavigate.mockReset();
  });

  it('requires both username and password before the browser allows submit', () => {
    renderLogin();
    expect(screen.getByPlaceholderText('admin')).toBeRequired();
    expect(screen.getByPlaceholderText('••••••••')).toBeRequired();
  });

  it('calls login with the entered credentials and navigates home on success', async () => {
    mockLogin.mockResolvedValueOnce(undefined);
    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByPlaceholderText('admin'), 'analyst1');
    await user.type(screen.getByPlaceholderText('••••••••'), 'password123');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('analyst1', 'password123');
    });
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('shows an error message and does not navigate on failed login', async () => {
    mockLogin.mockRejectedValueOnce(new Error('Invalid username or password'));
    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByPlaceholderText('admin'), 'analyst1');
    await user.type(screen.getByPlaceholderText('••••••••'), 'wrongpass');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByText('Invalid username or password')).toBeInTheDocument();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('clears a previous error on a new submit attempt', async () => {
    mockLogin.mockRejectedValueOnce(new Error('Invalid username or password'));
    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByPlaceholderText('admin'), 'analyst1');
    await user.type(screen.getByPlaceholderText('••••••••'), 'wrongpass');
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    expect(await screen.findByText('Invalid username or password')).toBeInTheDocument();

    mockLogin.mockResolvedValueOnce(undefined);
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.queryByText('Invalid username or password')).not.toBeInTheDocument();
    });
  });
});
