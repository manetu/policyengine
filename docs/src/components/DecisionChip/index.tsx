import React from 'react';
import Chip from '@mui/material/Chip';

type DecisionType = 'grant' | 'deny';

interface DecisionChipProps {
  decision: DecisionType;
  size?: 'small' | 'medium';
}

const decisionStyles: Record<DecisionType, { backgroundColor: string }> = {
  grant: {
    backgroundColor: '#2e7d32', // Green 800
  },
  deny: {
    backgroundColor: '#c62828', // Red 800
  },
};

const decisionLabels: Record<DecisionType, string> = {
  grant: 'GRANT',
  deny: 'DENY',
};

export default function DecisionChip({
  decision,
  size = 'small',
}: DecisionChipProps): React.ReactElement {
  const style = decisionStyles[decision];
  const label = decisionLabels[decision];

  return (
    <Chip
      label={label}
      size={size}
      sx={{
        backgroundColor: style.backgroundColor,
        color: '#ffffff',
        fontWeight: 700,
        fontSize: size === 'small' ? '0.75rem' : '0.85rem',
        height: size === 'small' ? '22px' : '26px',
        letterSpacing: '0.5px',
        '& .MuiChip-label': {
          padding: size === 'small' ? '0 10px' : '0 12px',
        },
      }}
    />
  );
}
