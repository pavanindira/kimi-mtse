import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import AdminReportTemplates from '../../pages/AdminReportTemplates';

const mockCreateMutateAsync = vi.fn();
const mockUpdateMutateAsync = vi.fn();
const mockDeleteMutateAsync = vi.fn();

const sampleTemplates = [
  { id: 1, name: 'Default Template', is_default: true, has_logo: false, created_at: null },
  { id: 2, name: 'Custom Template', is_default: false, has_logo: true, created_at: null },
];

const templateDetail = {
  id: 2, name: 'Custom Template', is_default: false, has_logo: true, created_at: null,
  html_template: '<html><body>{{ engagement.name }}</body></html>',
};

vi.mock('../../lib/hooks', () => ({
  useReportTemplates: () => ({ data: sampleTemplates, isLoading: false }),
  useUploadLogo: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteReportTemplate: () => ({ mutateAsync: mockDeleteMutateAsync, isPending: false }),
  useReportTemplateDetail: (id: number | null) => ({
    data: id === 2 ? templateDetail : undefined,
    isLoading: false,
  }),
  useCreateReportTemplate: () => ({ mutateAsync: mockCreateMutateAsync, isPending: false }),
  useUpdateReportTemplate: () => ({ mutateAsync: mockUpdateMutateAsync, isPending: false }),
  QK: { templates: ['report-templates'], templateDetail: (id: number) => ['report-template', id] },
}));

function renderPage() {
  const qc = new QueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <AdminReportTemplates />
    </QueryClientProvider>,
  );
}

describe('AdminReportTemplates', () => {
  beforeEach(() => {
    mockCreateMutateAsync.mockReset();
    mockUpdateMutateAsync.mockReset();
    mockDeleteMutateAsync.mockReset();
  });

  it('lists existing templates with default badge', () => {
    renderPage();
    expect(screen.getByText('Default Template')).toBeInTheDocument();
    expect(screen.getByText('Custom Template')).toBeInTheDocument();
    expect(screen.getByText('Default')).toBeInTheDocument();
  });

  it('disables delete for the default template', () => {
    renderPage();
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete' });
    // Default Template is first in the list.
    expect(deleteButtons[0]).toBeDisabled();
    expect(deleteButtons[1]).not.toBeDisabled();
  });

  it('creates a template with the entered name and HTML', async () => {
    mockCreateMutateAsync.mockResolvedValueOnce({ id: 99 });
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: '+ New Template' }));

    await user.type(screen.getByPlaceholderText('e.g. Acme Corp Branded Report'),
                    'New Client Report');
    await user.click(screen.getByRole('button', { name: /save template/i }));

    await waitFor(() => {
      expect(mockCreateMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'New Client Report' }),
      );
    });
    // Editor closes back to the list view on success.
    await waitFor(() => {
      expect(screen.queryByText('New Report Template')).not.toBeInTheDocument();
    });
  });

  it('requires a name before saving a new template', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: '+ New Template' }));
    await user.click(screen.getByRole('button', { name: /save template/i }));

    expect(await screen.findByText('Template name is required')).toBeInTheDocument();
    expect(mockCreateMutateAsync).not.toHaveBeenCalled();
  });

  it('shows the server-side syntax error message on a rejected save', async () => {
    mockCreateMutateAsync.mockRejectedValueOnce(
      new Error('Invalid template syntax: unexpected end of template (line 3)'),
    );
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: '+ New Template' }));
    await user.type(screen.getByPlaceholderText('e.g. Acme Corp Branded Report'), 'Broken');
    await user.click(screen.getByRole('button', { name: /save template/i }));

    expect(await screen.findByText(/Invalid template syntax/)).toBeInTheDocument();
  });

  it('pre-fills the editor with existing content when editing', async () => {
    const user = userEvent.setup();
    renderPage();
    const editButtons = screen.getAllByRole('button', { name: 'Edit HTML' });
    await user.click(editButtons[1]); // "Custom Template"

    expect(await screen.findByDisplayValue('Custom Template')).toBeInTheDocument();
    expect(screen.getByDisplayValue(templateDetail.html_template)).toBeInTheDocument();
  });

  it('saves edits via update, not create', async () => {
    mockUpdateMutateAsync.mockResolvedValueOnce({ id: 2 });
    const user = userEvent.setup();
    renderPage();
    const editButtons = screen.getAllByRole('button', { name: 'Edit HTML' });
    await user.click(editButtons[1]);

    const nameInput = await screen.findByDisplayValue('Custom Template');
    await user.clear(nameInput);
    await user.type(nameInput, 'Renamed Template');
    await user.click(screen.getByRole('button', { name: /save template/i }));

    await waitFor(() => {
      expect(mockUpdateMutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'Renamed Template' }),
      );
    });
    expect(mockCreateMutateAsync).not.toHaveBeenCalled();
  });

  it('cancel returns to the list without saving', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: '+ New Template' }));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(screen.queryByText('New Report Template')).not.toBeInTheDocument();
    expect(mockCreateMutateAsync).not.toHaveBeenCalled();
  });
});
