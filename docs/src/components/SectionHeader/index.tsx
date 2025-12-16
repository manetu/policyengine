import React from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';

// Import commonly used icons
import MemoryIcon from '@mui/icons-material/Memory';
import ViewInArIcon from '@mui/icons-material/ViewInAr';
import HubIcon from '@mui/icons-material/Hub';
import CodeIcon from '@mui/icons-material/Code';
import ApiIcon from '@mui/icons-material/Api';
import SecurityIcon from '@mui/icons-material/Security';
import GavelIcon from '@mui/icons-material/Gavel';
import LockIcon from '@mui/icons-material/Lock';
import BuildIcon from '@mui/icons-material/Build';
import FactCheckIcon from '@mui/icons-material/FactCheck';
import ScienceIcon from '@mui/icons-material/Science';
import DnsIcon from '@mui/icons-material/Dns';
import InfoIcon from '@mui/icons-material/Info';
import SpeedIcon from '@mui/icons-material/Speed';
import StorageIcon from '@mui/icons-material/Storage';
import SettingsIcon from '@mui/icons-material/Settings';
import ExtensionIcon from '@mui/icons-material/Extension';
import TerminalIcon from '@mui/icons-material/Terminal';

const iconMap: Record<string, React.ElementType> = {
  'standalone': MemoryIcon,
  'memory': MemoryIcon,
  'docker': ViewInArIcon,
  'kubernetes': HubIcon,
  'code': CodeIcon,
  'go': CodeIcon,
  'api': ApiIcon,
  'http': ApiIcon,
  'security': SecurityIcon,
  'pdp': GavelIcon,
  'pep': LockIcon,
  'build': BuildIcon,
  'lint': FactCheckIcon,
  'test': ScienceIcon,
  'serve': DnsIcon,
  'version': InfoIcon,
  'performance': SpeedIcon,
  'storage': StorageIcon,
  'settings': SettingsIcon,
  'integration': ExtensionIcon,
  'terminal': TerminalIcon,
};

interface SectionHeaderProps {
  icon: keyof typeof iconMap | string;
  children: React.ReactNode;
  level?: 2 | 3 | 4;
}

export default function SectionHeader({
  icon,
  children,
  level = 3,
}: SectionHeaderProps): React.ReactElement {
  const IconComponent = iconMap[icon.toLowerCase()] || SettingsIcon;
  const variant = `h${level}` as 'h2' | 'h3' | 'h4';

  const sizeMap = {
    2: '1.75rem',
    3: '1.5rem',
    4: '1.25rem',
  };

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.5,
        mb: 2,
        mt: level === 2 ? 4 : 3,
      }}
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: level === 2 ? 48 : 40,
          height: level === 2 ? 48 : 40,
          borderRadius: '8px',
          backgroundColor: 'var(--ifm-color-primary)',
          color: '#fff',
          flexShrink: 0,
        }}
      >
        <IconComponent sx={{ fontSize: sizeMap[level] }} />
      </Box>
      <Typography
        variant={variant}
        component={`h${level}`}
        sx={{
          fontSize: sizeMap[level],
          fontWeight: 700,
          margin: 0,
          color: 'var(--ifm-heading-color)',
        }}
      >
        {children}
      </Typography>
    </Box>
  );
}
