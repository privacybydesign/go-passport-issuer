import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from "react-router-dom";
import { useAppContext } from '../AppContext';

export default function IndexPage() {
  const { t, i18n } = useTranslation();
  const { session, setSession} = useAppContext();
  const [showError, setShowError] = useState(false);
  const navigate = useNavigate();
  
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();

    // call validate endpoint
    try {
      const response = await fetch('/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      if (data.error) {
        setShowError(true);
        return;
      }

      // Assuming the response contains a sessionId and nonce
      setSession({ sessionId: data.session_id, nonce: data.nonce });
    } catch (error) {
      console.error('Error during validation:', error);
      setShowError(true);
      return;
    }
  };

  return (
    <>
      <form id="container" onSubmit={submit}>
        <header>
          <h1>{t('index_header')}</h1>
        </header>
        <main>
          <div className="sms-form">
            <p>{t('index_explanation')}</p>
            <p>
              {showError && <div className="warning">{t('index_passport_not_valid')}</div>}
              { session && 
                <div>
                  <p>{t('index_session_id')}: {session.sessionId}</p>
                  <p>{t('index_nonce')}: {session.nonce}</p>
                </div>
                }
            </p>
          </div>
        </main>
        <footer>
          <div className="actions">
            <div></div>
            <button id="submit-button" type="submit">{t('index_start')}</button>
          </div>
        </footer>
      </form>
    </>
  );
}
