
import React, { useState, useCallback, useMemo, createContext, useContext, useEffect, useRef } from 'react';
import { Toaster, toast } from 'react-hot-toast';
import { translations, Language } from './utils/i18n';
import { HashRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import Layout from './components/layout/Layout';
import DashboardPage from './pages/DashboardPage';
import PlatformsPage from './pages/PlatformsPage';
import AgentsPage from './pages/AgentsPage';
import BotsPage from './pages/BotsPage';
import AppsPage from './pages/AppsPage';
import ApiGuidePage from './pages/ApiGuidePage';
import GenerateKeyPage from './pages/GenerateKeyPage';
import AgentDashboardPage from './pages/AgentDashboardPage';
import AgentKeysPage from './pages/AgentKeysPage';
import ChangePasswordPage from './pages/ChangePasswordPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import AgentProfilePage from './pages/AgentProfilePage';
import AgentUsagePage from './pages/AgentUsagePage';
import KeyLogsPage from './pages/KeyLogsPage';
import IpBanPage from './pages/IpBanPage';
import AgentMenusPage from './pages/AgentMenusPage';
import AgentGenerateKeyPage from './pages/AgentGenerateKeyPage';
import AgentAgentsPage from './pages/AgentAgentsPage';
import MaintenancePage from './pages/MaintenancePage';
import { Agent, Platform, Bot, StandaloneKey, KeyLog, MaintenanceConfig, Application } from './types';
import { getPlatforms, getAgents, getBots, getApplications, getStandaloneKeys, getKeyLogs, getAdminPassword, setAdminPassword, getMaintenanceConfig, saveMaintenanceConfig, deleteAgent } from './services/firebaseService';

type UserRole = 'admin' | 'agent';
interface User {
    role: UserRole;
    data: Agent | { username: string };
}

interface LoginOptions {
  clientIp?: string;
  skipMaintenanceCheck?: boolean;
}

interface AuthContextType {
  isAuthenticated: boolean;
  user: User | null;
  login: (username: string, password?: string, options?: LoginOptions) => Promise<'success' | 'banned' | 'invalid' | 'maintenance'>;
  logout: () => void;
  updateUserData: (data: Agent) => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface DataContextType {
    agents: Agent[];
    platforms: Platform[];
    bots: Bot[];
    applications: Application[];
    standaloneKeys: StandaloneKey[];
    keyLogs: KeyLog[];
    loading: boolean;
    refreshData: () => void;
}

const DataContext = createContext<DataContextType | null>(null);

export const useData = () => {
    const context = useContext(DataContext);
    if (!context) {
        throw new Error('useData must be used within a DataProvider');
    }
    return context;
}

interface Settings {
  notifications: boolean;
  darkMode: boolean;
  language: Language;
}

const defaultSettings: Settings = {
  notifications: true,
  darkMode: false,
  language: 'th',
};

interface SettingsContextType {
  settings: Settings;
  updateSettings: (s: Settings) => void;
  notify: (msg: string, type?: 'success' | 'error') => void;
  t: (key: keyof typeof translations['en']) => string;
}

const SettingsContext = createContext<SettingsContextType | null>(null);

export const useSettings = () => {
  const ctx = useContext(SettingsContext);
  if (!ctx) {
    throw new Error('useSettings must be used within SettingsProvider');
  }
  return ctx;
};

interface MaintenanceContextType {
  config: MaintenanceConfig;
  loading: boolean;
  refresh: () => Promise<void>;
  update: (config: MaintenanceConfig) => Promise<void>;
}

const MaintenanceContext = createContext<MaintenanceContextType | null>(null);

export const useMaintenance = () => {
  const ctx = useContext(MaintenanceContext);
  if (!ctx) {
    throw new Error('useMaintenance must be used within MaintenanceProvider');
  }
  return ctx;
};

const defaultMaintenanceState: MaintenanceConfig = {
  enabled: false,
  message: 'ระบบกำลังปิดปรับปรุงเพื่ออัปเดต',
  allowedAdminIps: [],
  scheduledStart: undefined,
  scheduledEnd: undefined,
};

const sanitizeIps = (ips?: string[]): string[] => {
  if (!Array.isArray(ips)) return [];
  return ips
    .map((ip) => (typeof ip === 'string' ? ip.trim() : ''))
    .filter((ip) => ip.length > 0);
};

const normalizeScheduleDate = (value?: string): string | undefined => {
  if (typeof value !== 'string') {
    return undefined;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return undefined;
  }
  return parsed.toISOString();
};

const normalizeMaintenanceConfig = (incoming?: MaintenanceConfig): MaintenanceConfig => {
  if (!incoming) {
    return { ...defaultMaintenanceState };
  }
  return {
    ...defaultMaintenanceState,
    ...incoming,
    allowedAdminIps: sanitizeIps(incoming.allowedAdminIps),
    scheduledStart: normalizeScheduleDate(incoming.scheduledStart),
    scheduledEnd: normalizeScheduleDate(incoming.scheduledEnd),
  };
};

const shouldAutoResumeMaintenance = (config: MaintenanceConfig, now: number = Date.now()): boolean => {
  if (!config.enabled || !config.scheduledEnd) {
    return false;
  }
  const endTime = new Date(config.scheduledEnd).getTime();
  if (Number.isNaN(endTime)) {
    return false;
  }
  return endTime <= now;
};

const isMaintenanceWindowActive = (config: MaintenanceConfig, now: number = Date.now()): boolean => {
  if (!config.enabled) {
    return false;
  }
  const startTime = config.scheduledStart ? new Date(config.scheduledStart).getTime() : undefined;
  const endTime = config.scheduledEnd ? new Date(config.scheduledEnd).getTime() : undefined;

  if (typeof startTime === 'number' && !Number.isNaN(startTime) && now < startTime) {
    return false;
  }

  if (typeof endTime === 'number' && !Number.isNaN(endTime) && now >= endTime) {
    return false;
  }

  return true;
};

const MaintenanceProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [config, setConfig] = useState<MaintenanceConfig>(defaultMaintenanceState);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const remote = await getMaintenanceConfig();
      const normalized = normalizeMaintenanceConfig(remote);
      const shouldResume = shouldAutoResumeMaintenance(normalized);
      const resolved = shouldResume
        ? { ...normalized, enabled: false, scheduledStart: undefined, scheduledEnd: undefined }
        : normalized;

      if (shouldResume) {
        try {
          await saveMaintenanceConfig(resolved);
        } catch (error) {
          console.error('Failed to auto resume maintenance config:', error);
        }
      }

      setConfig(resolved);
    } catch (error) {
      console.error('Failed to refresh maintenance config:', error);
      setConfig(defaultMaintenanceState);
    } finally {
      setLoading(false);
    }
  }, []);

  const update = useCallback(async (nextConfig: MaintenanceConfig) => {
    const normalized = normalizeMaintenanceConfig(nextConfig);
    const shouldResume = shouldAutoResumeMaintenance(normalized);
    const resolved = shouldResume
      ? { ...normalized, enabled: false, scheduledStart: undefined, scheduledEnd: undefined }
      : normalized;
    try {
      await saveMaintenanceConfig(resolved);
      setConfig(resolved);
    } catch (error) {
      console.error('Failed to save maintenance config:', error);
      throw error;
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    if (!config.enabled || !config.scheduledEnd) {
      return;
    }
    const endTime = new Date(config.scheduledEnd).getTime();
    if (Number.isNaN(endTime)) {
      return;
    }
    const delay = endTime - Date.now();
    if (delay <= 0) {
      refresh();
      return;
    }
    const timer = window.setTimeout(() => {
      refresh();
    }, delay + 1000);
    return () => window.clearTimeout(timer);
  }, [config.enabled, config.scheduledEnd, refresh]);

  const value = useMemo(
    () => ({ config, loading, refresh, update }),
    [config, loading, refresh, update]
  );

  return <MaintenanceContext.Provider value={value}>{children}</MaintenanceContext.Provider>;
};

const SettingsProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [settings, setSettings] = useState<Settings>(() => {
    const saved = localStorage.getItem('settings');
    return saved ? JSON.parse(saved) : defaultSettings;
  });

  useEffect(() => {
    const root = document.documentElement;
    if (settings.darkMode) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [settings.darkMode]);

  useEffect(() => {
    document.documentElement.setAttribute('lang', settings.language);
  }, [settings.language]);

  useEffect(() => {
    localStorage.setItem('settings', JSON.stringify(settings));
  }, [settings]);

  const updateSettings = (s: Settings) => setSettings(s);

  const notify = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    if (!settings.notifications) return;
    type === 'success' ? toast.success(message) : toast.error(message);
  }, [settings.notifications]);

  const t = useCallback((key: keyof typeof translations['en']) => {
    return translations[settings.language][key] || key;
  }, [settings.language]);

  return (
    <SettingsContext.Provider value={{ settings, updateSettings, notify, t }}>
      {children}
    </SettingsContext.Provider>
  );
};

const DataProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [agents, setAgents] = useState<Agent[]>([]);
    const [platforms, setPlatforms] = useState<Platform[]>([]);
    const [bots, setBots] = useState<Bot[]>([]);
    const [applications, setApplications] = useState<Application[]>([]);
    const [standaloneKeys, setStandaloneKeys] = useState<StandaloneKey[]>([]);
    const [keyLogs, setKeyLogs] = useState<KeyLog[]>([]);
    const [loading, setLoading] = useState(true);
    const expiryTimers = useRef<Map<string, number>>(new Map());

    const clearExpiryTimer = useCallback((agentId: string) => {
        if (typeof window === 'undefined') {
            return;
        }
        const existingTimer = expiryTimers.current.get(agentId);
        if (existingTimer) {
            window.clearTimeout(existingTimer);
            expiryTimers.current.delete(agentId);
        }
    }, []);

    const scheduleAgentExpiry = useCallback((agent: Agent) => {
        if (typeof window === 'undefined') {
            return;
        }

        clearExpiryTimer(agent.id);

        if (!agent.expiresAt) {
            return;
        }

        const expiresAt = new Date(agent.expiresAt).getTime();
        if (Number.isNaN(expiresAt)) {
            return;
        }

        const delay = expiresAt - Date.now();

        if (delay <= 0) {
            deleteAgent(agent.id)
                .catch((error) => {
                    console.error('Failed to auto delete expired agent:', error);
                })
                .finally(() => {
                    setAgents((prev) => prev.filter((existing) => existing.id !== agent.id));
                    clearExpiryTimer(agent.id);
                });
            return;
        }

        const timeoutId = window.setTimeout(async () => {
            try {
                await deleteAgent(agent.id);
            } catch (error) {
                console.error('Failed to auto delete expired agent:', error);
            } finally {
                setAgents((prev) => prev.filter((existing) => existing.id !== agent.id));
                clearExpiryTimer(agent.id);
            }
        }, delay);

        expiryTimers.current.set(agent.id, timeoutId);
    }, [clearExpiryTimer]);

    const fetchData = useCallback(async () => {
        setLoading(true);
        try {
            const [platformsData, agentsData, botsData, appsData, keysData, logsData] = await Promise.all([
                getPlatforms(),
                getAgents(),
                getBots(),
                getApplications(),
                getStandaloneKeys(),
                getKeyLogs(),
            ]);
            const now = Date.now();
            const activeAgents: Agent[] = [];
            const expiredAgents: Agent[] = [];

            agentsData.forEach((agent) => {
                if (agent.expiresAt) {
                    const expiresAt = new Date(agent.expiresAt).getTime();
                    if (!Number.isNaN(expiresAt) && expiresAt <= now) {
                        expiredAgents.push(agent);
                        return;
                    }
                }
                activeAgents.push(agent);
            });

            if (expiredAgents.length > 0) {
                await Promise.all(
                    expiredAgents.map((agent) =>
                        deleteAgent(agent.id).catch((error) => {
                            console.error('Failed to delete expired agent during sync:', error);
                        }),
                    ),
                );
            }

            setPlatforms(platformsData);
            setAgents(activeAgents);
            setBots(botsData);
            setApplications(appsData);
            setStandaloneKeys(keysData);
            setKeyLogs(logsData);

            if (typeof window !== 'undefined') {
                const activeIds = new Set(activeAgents.map((agent) => agent.id));
                activeAgents.forEach((agent) => {
                    scheduleAgentExpiry(agent);
                });

                expiryTimers.current.forEach((timerId, agentId) => {
                    if (!activeIds.has(agentId)) {
                        window.clearTimeout(timerId);
                        expiryTimers.current.delete(agentId);
                    }
                });
            }
        } catch (error) {
            console.error("Failed to fetch data:", error);
        } finally {
            setLoading(false);
        }
    }, [scheduleAgentExpiry]);

    useEffect(() => {
        fetchData();
    }, [fetchData]);

    useEffect(() => () => {
        if (typeof window === 'undefined') {
            return;
        }
        expiryTimers.current.forEach((timerId) => {
            window.clearTimeout(timerId);
        });
        expiryTimers.current.clear();
    }, []);

    const value = useMemo(() => ({
        agents,
        platforms,
        bots,
        applications,
        standaloneKeys,
        keyLogs,
        loading,
        refreshData: fetchData,
    }), [agents, platforms, bots, applications, standaloneKeys, keyLogs, loading, fetchData]);
    
    return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
};

const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [user, setUser] = useState<User | null>(() => {
        const storedUser = sessionStorage.getItem('user');
        return storedUser ? JSON.parse(storedUser) : null;
    });

    const login = useCallback(async (username: string, password?: string, options?: LoginOptions): Promise<'success' | 'banned' | 'invalid' | 'maintenance'> => {
        if (!options?.skipMaintenanceCheck) {
            try {
                const maintenance = await getMaintenanceConfig();
                let normalizedMaintenance = normalizeMaintenanceConfig(maintenance);
                if (shouldAutoResumeMaintenance(normalizedMaintenance)) {
                    const resumedMaintenance = {
                        ...normalizedMaintenance,
                        enabled: false,
                        scheduledStart: undefined,
                        scheduledEnd: undefined,
                    };
                    try {
                        await saveMaintenanceConfig(resumedMaintenance);
                    } catch (error) {
                        console.error('Failed to auto resume maintenance config during login:', error);
                    }
                    normalizedMaintenance = resumedMaintenance;
                }

                if (isMaintenanceWindowActive(normalizedMaintenance)) {
                    const allowedIps = sanitizeIps(normalizedMaintenance.allowedAdminIps);
                    const ipAllowed = options?.clientIp ? allowedIps.includes(options.clientIp.trim()) : false;
                    const isAdminAttempt = username === 'admin';
                    if (!isAdminAttempt || !ipAllowed) {
                        return 'maintenance';
                    }
                }
            } catch (error) {
                console.error('Failed to check maintenance mode during login:', error);
            }
        }

        // Admin Login
        if (username === 'admin' && typeof password === 'string') {
            const { password: storedAdminPassword, source } = await getAdminPassword();
            if (password === storedAdminPassword) {
                if (source !== 'remote') {
                    try {
                        await setAdminPassword(storedAdminPassword);
                    } catch (error) {
                        console.error('Failed to sync admin password to database:', error);
                    }
                }
                const adminUser: User = { role: 'admin', data: { username: 'admin' } };
                sessionStorage.setItem('user', JSON.stringify(adminUser));
                setUser(adminUser);
                return 'success';
            }
        }

        // Agent Login
        try {
            const agents = await getAgents();
            const foundAgent = agents.find(agent => agent.username === username && agent.password === password);
            if (foundAgent) {
                if (foundAgent.expiresAt) {
                    const expiresAt = new Date(foundAgent.expiresAt).getTime();
                    if (!Number.isNaN(expiresAt) && expiresAt <= Date.now()) {
                        try {
                            await deleteAgent(foundAgent.id);
                        } catch (error) {
                            console.error('Failed to delete expired agent during login:', error);
                        }
                        return 'invalid';
                    }
                }
                if (foundAgent.status === 'banned') {
                    return 'banned';
                }
                const agentUser: User = { role: 'agent', data: foundAgent };
                sessionStorage.setItem('user', JSON.stringify(agentUser));
                setUser(agentUser);
                return 'success';
            }
        } catch (error) {
            console.error("Error fetching agents for login:", error);
        }

        return 'invalid';
    }, []);

    const logout = useCallback(() => {
        sessionStorage.removeItem('user');
        setUser(null);
    }, []);

    const updateUserData = useCallback((data: Agent) => {
        if (!user) return;
        const newUser: User = { ...user, data };
        sessionStorage.setItem('user', JSON.stringify(newUser));
        setUser(newUser);
    }, [user]);

    const authContextValue = useMemo(() => ({
        isAuthenticated: !!user,
        user,
        login,
        logout,
        updateUserData,
    }), [user, login, logout, updateUserData]);

    return (
        <AuthContext.Provider value={authContextValue}>
            {children}
        </AuthContext.Provider>
    );
};


const App: React.FC = () => {
  return (
    <SettingsProvider>
      <MaintenanceProvider>
        <AuthProvider>
          <DataProvider>
            <AppRoutes />
            <Toaster position="top-right" />
          </DataProvider>
        </AuthProvider>
      </MaintenanceProvider>
    </SettingsProvider>
  );
};

const AppRoutes: React.FC = () => {
    const { isAuthenticated } = useAuth();
    return (
        <HashRouter>
            <Routes>
                <Route path="/login" element={!isAuthenticated ? <LoginPage /> : <Navigate to="/" />} />
                <Route path="/*" element={isAuthenticated ? <ProtectedRoutes /> : <Navigate to="/login" />} />
            </Routes>
        </HashRouter>
    );
}

const ProtectedRoutes: React.FC = () => {
    const { user } = useAuth();

    if (!user) return <Navigate to="/login" />;

    return (
        <Layout>
            {user.role === 'admin' && <AdminRoutes />}
            {user.role === 'agent' && <AgentRoutes />}
        </Layout>
    );
};

const AdminRoutes: React.FC = () => (
    <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/platforms" element={<PlatformsPage />} />
        <Route path="/agents" element={<AgentsPage />} />
        <Route path="/agent-menus" element={<AgentMenusPage />} />
        <Route path="/generate-key" element={<GenerateKeyPage />} />
        <Route path="/bots" element={<BotsPage />} />
        <Route path="/apps" element={<AppsPage />} />
        <Route path="/api-guide" element={<ApiGuidePage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/maintenance" element={<MaintenancePage />} />
        <Route path="/logs" element={<KeyLogsPage />} />
        <Route path="/ip-bans" element={<IpBanPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/change-password" element={<ChangePasswordPage />} />
        <Route path="*" element={<Navigate to="/" />} />
    </Routes>
);

const AgentRoutes: React.FC = () => (
    <Routes>
        <Route path="/" element={<AgentDashboardPage />} />
        <Route path="/my-keys" element={<AgentKeysPage />} />
        <Route path="/generate-key" element={<AgentGenerateKeyPage />} />
        <Route path="/bots" element={<BotsPage />} />
        <Route path="/apps" element={<AppsPage />} />
        <Route path="/profile" element={<AgentProfilePage />} />
        <Route path="/agents" element={<AgentAgentsPage />} />
        <Route path="/usage" element={<AgentUsagePage />} />
        <Route path="/logs" element={<KeyLogsPage />} />
        <Route path="/ip-bans" element={<IpBanPage />} />
        <Route path="/change-password" element={<ChangePasswordPage />} />
        <Route path="*" element={<Navigate to="/" />} />
    </Routes>
);

export default App;
