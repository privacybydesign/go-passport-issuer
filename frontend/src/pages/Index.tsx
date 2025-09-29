
import { useTranslation } from 'react-i18next';

export default function IndexPage() {
  const { t, i18n } = useTranslation();

  return (
    <>
      <div id="container">
        <header>
          <h1>{t('index_header')}</h1>
        </header>
        <main>
          <div className="sms-form">
            <div className="store-update">
              <p>{t('index_store_update_title')}</p>
              <p>{t('index_store_update_description')}</p>
              <div className="store-links">
                <a href="https://apps.apple.com/nl/app/irma-authenticatie/id1294092994" className="store-link">
                  <img src="/images/appstore.svg" alt="app store" />
                </a>
                <a href="https://play.google.com/store/apps/details?id=org.irmacard.cardemu" className="store-link">
                  <img src="/images/playstore.svg" alt="google play store" />
                </a>
                <a href="https://f-droid.org/en/packages/org.irmacard.cardemu/" className="store-link">
                  <img src="/images/fdroid.svg" alt="f droid" />
                </a>
              </div>
            </div>
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
