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
                    index_start: "Add passport",
                }
            },
            nl: {
                translation: {
                    index_title: "Paspoort toevoegen",
                    index_header: "Paspoort toevoegen",
                    index_explanation: "Zet je paspoortgegevens in je Yivi-app.",
                    index_start: "Paspoort toevoegen",
                }
            }
        },
        lng: 'nl', // default language
        fallbackLng: 'en',

        interpolation: {
            escapeValue: false, // react already escapes
        }
    });

export default i18n;
