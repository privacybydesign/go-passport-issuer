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
        const encodedData = queryParams.get('data');

        if (!encodedData) {
            console.error("No data parameter found in callback URL");
            setShowError(true);
            return;
        }

        try {
            // Decode base64 string to JSON
            const decodedString = atob(encodedData);
            const payload = JSON.parse(decodedString);

            import("@privacybydesign/yivi-frontend").then((yivi) => {
                const web = yivi.newWeb({
                    debugging: true,
                    language: i18n.language,
                    element: '#yivi-web-form',

                    // Back-end options
                    session: {
                        url: payload.irma_server_url,

                        start: {
                            method: 'POST',
                            body: payload.jwt,
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

        }, [location.search]);


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
                                <p>{t('information')}</p>
                                <p>{t('qr')}</p>

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
