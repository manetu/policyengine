import React from 'react';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import RemoveCircleOutlineIcon from '@mui/icons-material/RemoveCircleOutline';

type CheckVariant = 'yes' | 'no' | 'partial' | 'na';

interface FeatureCheckProps {
  variant?: CheckVariant;
  size?: 'small' | 'medium';
}

const variantConfig: Record<CheckVariant, { Icon: React.ElementType; color: string; label: string }> = {
  yes: {
    Icon: CheckCircleIcon,
    color: '#38a169', // Green
    label: 'Yes',
  },
  no: {
    Icon: RadioButtonUncheckedIcon,
    color: '#a0aec0', // Gray
    label: 'No',
  },
  partial: {
    Icon: RemoveCircleOutlineIcon,
    color: '#ed8936', // Orange
    label: 'Partial',
  },
  na: {
    Icon: RemoveCircleOutlineIcon,
    color: '#718096', // Dark gray
    label: 'N/A',
  },
};

export default function FeatureCheck({
  variant = 'yes',
  size = 'medium',
}: FeatureCheckProps): React.ReactElement {
  const { Icon, color, label } = variantConfig[variant];
  const fontSize = size === 'small' ? '1rem' : '1.25rem';

  return (
    <Icon
      sx={{
        fontSize,
        color,
        verticalAlign: 'middle',
      }}
      aria-label={label}
      titleAccess={label}
    />
  );
}
