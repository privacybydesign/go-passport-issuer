import React, { createContext, useContext, useState, ReactNode } from "react";

interface Session {
  sessionId: string | undefined;
  nonce: string | undefined;
};

// Define the shape of the context state
interface AppContextType {
  session: Session | undefined;
  setSession: (value: Session) => void;
}

// Create the context with a default value of undefined
const AppContext = createContext<AppContextType | undefined>(undefined);

// Define the props for the provider
interface AppProviderProps {
  children: ReactNode;
}

// Provider component
export const AppProvider: React.FC<AppProviderProps> = ({ children }) => {
  const [session, setSession] = useState<Session | undefined>();

  return (
    <AppContext.Provider value={{ session, setSession }}>
      {children}
    </AppContext.Provider>
  );
};

// Custom hook for consuming the context
export const useAppContext = (): AppContextType => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error("useAppContext must be used within an AppProvider");
  }
  return context;
};