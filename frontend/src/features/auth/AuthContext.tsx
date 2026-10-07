import React, { useState, useEffect, useCallback } from 'react';
import { User, LoginCredentials, RegisterCredentials } from '../../types';
import { loginApi, registerApi, getMeApi } from '../../services/api';
import { AuthContext } from './context';

const TOKEN_STORAGE_KEY = 'cybershield_auth_token';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => {
    return sessionStorage.getItem(TOKEN_STORAGE_KEY);
  });
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Load and verify existing session from token on startup
  const initAuth = useCallback(async () => {
    const storedToken = sessionStorage.getItem(TOKEN_STORAGE_KEY);
    if (!storedToken) {
      setUser(null);
      setToken(null);
      setIsLoading(false);
      return;
    }

    try {
      const profile = await getMeApi(storedToken);
      setUser(profile);
      setToken(storedToken);
    } catch {
      // Token is expired, invalid, or server rejected it
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
      setUser(null);
      setToken(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    initAuth();
  }, [initAuth]);

  const login = async (credentials: LoginCredentials) => {
    const response = await loginApi(credentials);
    sessionStorage.setItem(TOKEN_STORAGE_KEY, response.access_token);
    setToken(response.access_token);
    setUser(response.user);
  };

  const register = async (credentials: RegisterCredentials) => {
    const newUser = await registerApi(credentials);
    return newUser;
  };

  const logout = () => {
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    setToken(null);
    setUser(null);
  };

  const refreshUser = async () => {
    if (!token) return;
    try {
      const profile = await getMeApi(token);
      setUser(profile);
    } catch {
      logout();
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user && !!token,
        isLoading,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
