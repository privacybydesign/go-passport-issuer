import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import i18n from '../i18n';

export default function CallbackPage() {
    const { t } = useTranslation();
    const [error, setError] = useState(false);
    const [done, setDone] = useState(false);

    const [showError, setShowError] = useState(false);

    useEffect(() => {
        const queryParams = new URLSearchParams(location.search);
        const irmaServerUrl = queryParams.get('irmaServerUrl');
        const jwt = queryParams.get('jwt');
        if (!irmaServerUrl || !jwt) {
            setShowError(true);
            return;
        }

        const decodedIrmaServerUrl = atob(irmaServerUrl);
        const decodedJwt = atob(jwt);

        startIrmaSession(decodedJwt, decodedIrmaServerUrl);

    }, [location.search]);

    const startIrmaSession = (jwt: string, irma_server_url: string) => {
        try {
            import("@privacybydesign/yivi-frontend").then((yivi) => {
                const web = yivi.newWeb({
                    debugging: true,
                    language: i18n.language,
                    element: '#yivi-web-form',

                    // Back-end options
                    session: {
                        url: irma_server_url,

                        start: {
                            method: 'POST',
                            body: jwt,
                            headers: { 'Content-Type': 'text/plain' },
                        }
                    }
                });
                web.start()
                    .then(() => {
                        setDone(true);
                    })
                    .catch((err: any) => {
                        console.error('Error starting Yivi:', err);
                        setError(true);
                    });
            });
        } catch (err: any) {
            console.error("Error during callback processing:", err);
            setShowError(true);
        }
    }

    return (
        <>
            <div id="container">
                <header>
                    <h1>{t('index_header')}</h1>
                </header>
                <main>
                    <div className="sms-form">
                        <p>{t('index_explanation')}</p>
                        {error && (
                            <div className="imageContainer">
                                <img src="/images/fail.png" alt="error" />
                            </div>
                        )}
                        {!error && !done && (
                            <>
                                <div id="yivi-web-form">
                                </div>
                            </>
                        )}
                        {done && (
                            <div className="imageContainer">
                                <img src="/images/done.png" alt="error" />
                                <p>{t('thank_you')}</p>
                            </div>
                        )}
                    </div>
                </main>
                <footer>
                    <div className="actions">
                        <div></div>
                    </div>
                </footer>
            </div>
        </>
    );

    
}
