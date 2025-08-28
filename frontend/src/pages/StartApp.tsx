import { useTranslation } from 'react-i18next';

export default function StartAppPage() {
    const { t } = useTranslation();

    return (
        <>
            <div id="container">
                <header>
                    <h1>{t('start_app_title')}</h1>
                </header>
                <main>
                    <div className="sms-form">
                        <p>{t('start_app_explanation')}</p>
                        <p>You should download the Verifiable Credentials from MRTD app.</p>
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
