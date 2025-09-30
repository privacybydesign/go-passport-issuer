import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

i18n
    .use(LanguageDetector)
    .use(initReactI18next).init({
        detection: {
            order: ['path', 'navigator'],
            lookupFromPathIndex: 0
        },
        resources: {
            en: {
                translation: {
                    index_title: "Add passport",
                    index_header: "Add passport",
                    index_explanation: "Add your passport details in your Yivi app.",
                    index_store_update_description: "Passport readout was recently added to the Yivi app. Update via one of the stores below to start using it.",
                    index_start: "Add passport",
                    index_error: "Something went wrong please try again.",
                    start_app_title: "Download VC MRTD App",
                    start_app_explanation: "Think link is supposed to open the VC MRTD App, make sure to open this URL on a mobile phone.",
                }
            },
            nl: {
                translation: {
                    index_title: "Paspoort toevoegen",
                    index_header: "Paspoort toevoegen",
                    index_explanation: "Zet je paspoortgegevens in je Yivi-app.",
                    index_store_update_description: "Paspoort uitlezen is onlangs toegevoegd aan de Yivi-app. Werk de app bij via een van de onderstaande winkels om het te gebruiken.",
                    index_start: "Paspoort toevoegen",
                    index_error: "Er is iets misgegaan, probeer het opnieuw.",
                    start_app_title: "Download VC MRTD App",
                    start_app_explanation: "Deze link zou de VC MRTD-app moeten openen. Zorg ervoor dat je deze URL op een mobiele telefoon opent.",
                }
            }
        },
        lng: 'nl', // default language
        fallbackLng: 'en',

        interpolation: {
            escapeValue: false, // react already escapes
        }
    });

export { i18n };
