import React from 'react';
import Box from '@mui/material/Box';

// Import commonly used icons
import RocketLaunchIcon from '@mui/icons-material/RocketLaunch';
import FlashOnIcon from '@mui/icons-material/FlashOn';
import SchoolIcon from '@mui/icons-material/School';
import ExtensionIcon from '@mui/icons-material/Extension';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import BuildIcon from '@mui/icons-material/Build';
import FactCheckIcon from '@mui/icons-material/FactCheck';
import ScienceIcon from '@mui/icons-material/Science';
import DnsIcon from '@mui/icons-material/Dns';
import InfoIcon from '@mui/icons-material/Info';
import SecurityIcon from '@mui/icons-material/Security';
import LabelIcon from '@mui/icons-material/Label';
import BadgeIcon from '@mui/icons-material/Badge';
import GroupIcon from '@mui/icons-material/Group';
import InventoryIcon from '@mui/icons-material/Inventory';
import GavelIcon from '@mui/icons-material/Gavel';
import TuneIcon from '@mui/icons-material/Tune';
import MemoryIcon from '@mui/icons-material/Memory';
import ViewInArIcon from '@mui/icons-material/ViewInAr';
import HubIcon from '@mui/icons-material/Hub';
import CodeIcon from '@mui/icons-material/Code';
import ApiIcon from '@mui/icons-material/Api';
import LockIcon from '@mui/icons-material/Lock';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import SettingsIcon from '@mui/icons-material/Settings';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import LayersIcon from '@mui/icons-material/Layers';
import FolderSpecialIcon from '@mui/icons-material/FolderSpecial';
import LibraryBooksIcon from '@mui/icons-material/LibraryBooks';
import EditAttributesIcon from '@mui/icons-material/EditAttributes';
import TransformIcon from '@mui/icons-material/Transform';
import LinkIcon from '@mui/icons-material/Link';
import TerminalIcon from '@mui/icons-material/Terminal';
import BusinessIcon from '@mui/icons-material/Business';
import DownloadIcon from '@mui/icons-material/Download';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import ArchitectureIcon from '@mui/icons-material/Architecture';
import BlockIcon from '@mui/icons-material/Block';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ReplayIcon from '@mui/icons-material/Replay';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import LanguageIcon from '@mui/icons-material/Language';
import ScaleIcon from '@mui/icons-material/Scale';
import PublishIcon from '@mui/icons-material/Publish';
import UpdateIcon from '@mui/icons-material/Update';
import DevicesIcon from '@mui/icons-material/Devices';

const iconMap: Record<string, React.ElementType> = {
  // Navigation & Sections
  'rocket': RocketLaunchIcon,
  'flash': FlashOnIcon,
  'school': SchoolIcon,
  'extension': ExtensionIcon,
  'book': MenuBookIcon,
  'cloud': CloudUploadIcon,

  // CLI Commands
  'build': BuildIcon,
  'lint': FactCheckIcon,
  'test': ScienceIcon,
  'serve': DnsIcon,
  'version': InfoIcon,
  'terminal': TerminalIcon,

  // Concepts
  'security': SecurityIcon,
  'label': LabelIcon,
  'badge': BadgeIcon,
  'group': GroupIcon,
  'inventory': InventoryIcon,
  'gavel': GavelIcon,
  'tune': TuneIcon,
  'settings': SettingsIcon,
  'tree': AccountTreeIcon,
  'layers': LayersIcon,
  'folder': FolderSpecialIcon,
  'library': LibraryBooksIcon,
  'attributes': EditAttributesIcon,
  'transform': TransformIcon,
  'link': LinkIcon,
  'play': PlayArrowIcon,

  // Deployment
  'memory': MemoryIcon,
  'docker': ViewInArIcon,
  'kubernetes': HubIcon,

  // Integration
  'code': CodeIcon,
  'api': ApiIcon,
  'lock': LockIcon,

  // Enterprise
  'business': BusinessIcon,

  // Downloads
  'download': DownloadIcon,
  'file-download': FileDownloadIcon,

  // Architecture & Platform
  'architecture': ArchitectureIcon,
  'block': BlockIcon,
  'visibility': VisibilityIcon,
  'replay': ReplayIcon,
  'trending': TrendingUpIcon,
  'language': LanguageIcon,
  'scale': ScaleIcon,
  'deployment': PublishIcon,
  'update': UpdateIcon,
  'platform': DevicesIcon,
};

type IconSize = 'small' | 'medium' | 'large';

interface IconTextProps {
  icon: keyof typeof iconMap | string;
  children?: React.ReactNode;
  size?: IconSize;
  color?: string;
  gap?: number;
}

const sizeMap: Record<IconSize, string> = {
  small: '1rem',
  medium: '1.25rem',
  large: '1.5rem',
};

export default function IconText({
  icon,
  children,
  size = 'medium',
  color = 'var(--ifm-color-primary)',
  gap = 0.5,
}: IconTextProps): React.ReactElement | null {
  const IconComponent = iconMap[icon.toLowerCase()];

  if (!IconComponent) {
    console.warn(`IconText: Unknown icon "${icon}"`);
    return <>{children}</>;
  }

  return (
    <Box
      component="span"
      sx={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: gap,
        verticalAlign: 'middle',
      }}
    >
      <IconComponent
        sx={{
          fontSize: sizeMap[size],
          color: color,
        }}
      />
      {children && <span>{children}</span>}
    </Box>
  );
}
