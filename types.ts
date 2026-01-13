
export interface ApiKey {
  key: string;
  tokens_remaining: number;
  status: 'active' | 'inactive';
  createdAt: string;
}

export interface CreditHistoryEntry {
  date: string;
  action: string;
  amount: number; // positive for additions, negative for deductions
  balanceAfter: number;
}

export interface Agent {
  id: string;
  username: string;
  password?: string;
  credits: number;
  keys?: {
    [platformId: string]: ApiKey[];
  };
  createdAt: string;
  creditHistory?: CreditHistoryEntry[];
  user?: null; // Added for future use
  status?: 'active' | 'suspended' | 'banned';
  ipBanEnabled?: boolean;
  parentId?: string;
  welcomeAcknowledged?: boolean;
  welcomeAcknowledgedAt?: string;
  expiresAt?: string;
}

export interface StandaloneKey extends ApiKey {
    id: string;
    platformId: string;
    platformTitle: string;
}

export interface Platform {
  id: string;
  title: string;
  prefix: string;
  pattern: number[];
  apiEnabled?: boolean;
}

export interface Bot {
    id: string;
    name: string;
    url: string;
    addedAt: string;
    tokenCost: number;
}

export interface Application {
    id: string;
    name: string;
    url: string;
    addedAt: string;
    tokenCost: number;
}

export interface KeyLog {
    id: string;
    key: string;
    agentId: string;
    ip: string;
    usedAt: string;
    tokensUsed?: number;
}

export interface IpBan {
    id: string;
    ip: string;
    userId: string;
    createdAt: string;
}

export interface MaintenanceConfig {
    enabled: boolean;
    message?: string;
    allowedAdminIps?: string[];
    updatedAt?: string;
    updatedBy?: string;
    scheduledStart?: string;
    scheduledEnd?: string;
}
