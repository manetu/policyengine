import React from 'react';
import Box from '@mui/material/Box';

interface TableSectionProps {
  children: React.ReactNode;
}

export default function TableSection({
  children,
}: TableSectionProps): React.ReactElement {
  return (
    <Box
      component="span"
      className="table-section"
      sx={{
        display: 'inline-flex',
        alignItems: 'center',
        color: 'var(--ifm-color-primary)',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        fontSize: '0.85em',
        fontWeight: 700,
      }}
    >
      {children}
    </Box>
  );
}
