import React from 'react';
import Chip from '@mui/material/Chip';

type ChipVariant = 'premium' | 'community' | 'new' | 'beta' | 'deprecated';

interface FeatureChipProps {
  variant?: ChipVariant;
  label?: string;
  size?: 'small' | 'medium';
}

const variantStyles: Record<ChipVariant, { borderColor: string; backgroundColor: string; color: string }> = {
  premium: {
    borderColor: 'rgba(3, 163, 237, 1)', // Primary blue
    backgroundColor: 'rgba(3, 163, 237, 0.15)',
    color: 'rgba(3, 163, 237, 1)',
  },
  community: {
    borderColor: 'rgba(56, 161, 105, 1)', // Green
    backgroundColor: 'rgba(56, 161, 105, 0.15)',
    color: 'rgba(56, 161, 105, 1)',
  },
  new: {
    borderColor: 'rgba(128, 90, 213, 1)', // Purple
    backgroundColor: 'rgba(128, 90, 213, 0.15)',
    color: 'rgba(128, 90, 213, 1)',
  },
  beta: {
    borderColor: 'rgba(237, 137, 54, 1)', // Orange
    backgroundColor: 'rgba(237, 137, 54, 0.15)',
    color: 'rgba(237, 137, 54, 1)',
  },
  deprecated: {
    borderColor: 'rgba(113, 128, 150, 1)', // Gray
    backgroundColor: 'rgba(113, 128, 150, 0.15)',
    color: 'rgba(113, 128, 150, 1)',
  },
};

const variantLabels: Record<ChipVariant, string> = {
  premium: 'Premium',
  community: 'Community',
  new: 'New',
  beta: 'Beta',
  deprecated: 'Deprecated',
};

export default function FeatureChip({
  variant = 'premium',
  label,
  size = 'small',
}: FeatureChipProps): React.ReactElement {
  const style = variantStyles[variant];
  const displayLabel = label || variantLabels[variant];

  return (
    <Chip
      label={displayLabel}
      size={size}
      variant="outlined"
      sx={{
        borderColor: style.borderColor,
        backgroundColor: style.backgroundColor,
        color: style.color,
        fontWeight: 600,
        fontSize: size === 'small' ? '0.7rem' : '0.8rem',
        height: size === 'small' ? '20px' : '24px',
        marginLeft: '8px',
        verticalAlign: 'middle',
        '& .MuiChip-label': {
          padding: size === 'small' ? '0 8px' : '0 10px',
        },
      }}
    />
  );
}
