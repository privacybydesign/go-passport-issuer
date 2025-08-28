import { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { AppProvider } from "./AppContext";

import IndexPage from './pages/Index';
import CallbackPage from './pages/Callback';
import StartAppPage from './pages/StartApp';

import './i18n';

// Wrapper that sets the language based on the URL
function LanguageRouter() {
  const { lang } = useParams();
  const { i18n } = useTranslation();

  useEffect(() => {
    if (lang && i18n.language !== lang) {
      i18n.changeLanguage(lang);
    }
  }, [lang, i18n]);

  return (
    <Routes>
      <Route path="/" element={<IndexPage />} />
    </Routes>
  );
}

function App() {
  return (
    <AppProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/nl" replace />} />
          <Route path="/start-app" element={<StartAppPage />} />
          <Route path="/callback" element={<CallbackPage />} />
          <Route path=":lang/*" element={<LanguageRouter />} />
        </Routes>
      </BrowserRouter>
    </AppProvider>
  );
}

export default App;