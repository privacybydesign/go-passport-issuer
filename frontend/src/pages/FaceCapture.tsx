import { useEffect, useRef, useState } from 'react';
import {
    FaceLivenessType,
    type FaceLivenessSettings,
    type FaceLivenessWebComponent,
} from '@regulaforensics/vp-frontend-face-components';
import { faceCaptureOutcome, type FaceCaptureMessage } from '../faceCaptureOutcome';

/**
 * The JavaScript channel the Yivi app's WebView installs on the page
 * (`addJavaScriptChannel("YiviFace", …)`), used to hand the liveness outcome
 * back to the app. Absent when the page is opened in an ordinary browser, which
 * is how this page is checked by hand.
 */
declare global {
    interface Window {
        YiviFace?: { postMessage: (message: string) => void };
    }
}

/** Yivi palette, matching App.css and the app's own liveness screens. */
const yiviCustomization: FaceLivenessSettings['customization'] = {
    fontFamily: "'Open Sans', Verdana, Arial, sans-serif",
    onboardingScreenStartButtonBackground: '#E12747',
    onboardingScreenStartButtonBackgroundHover: '#C30025',
    onboardingScreenStartButtonTitle: '#FFFFFF',
    onboardingScreenStartButtonTitleHover: '#FFFFFF',
    retryScreenRetryButtonBackground: '#E12747',
    retryScreenRetryButtonBackgroundHover: '#C30025',
    retryScreenRetryButtonTitle: '#FFFFFF',
    retryScreenRetryButtonTitleHover: '#FFFFFF',
    processingScreenProgress: '#E12747',
    cameraScreenSectorActive: '#E12747',
    cameraScreenSectorTarget: '#96C5E1',
};

/**
 * Liveness capture page for the F-Droid build of the Yivi app.
 *
 * The F-Droid APK ships no proprietary Regula binaries, so instead of the native
 * Face SDK it opens this page in a WebView and runs Regula's web face component
 * here. The liveness session goes directly to the Regula Face API — the same
 * service the native SDK calls in the Play Store and App Store builds — and only
 * the resulting transaction id and verdict are handed back to the app, which
 * attaches the id to its issuance request for the backend to match against the
 * chip portrait.
 *
 * See privacybydesign/irmamobile#665.
 */
export default function FaceCapturePage() {
    const containerRef = useRef<HTMLDivElement>(null);
    // Set before any await so a late outcome (e.g. the component reporting an
    // error as the user also closes) cannot post a second message.
    const resolvedRef = useRef(false);
    const [error, setError] = useState<string | null>(null);
    const [outcome, setOutcome] = useState<FaceCaptureMessage | null>(null);

    useEffect(() => {
        const container = containerRef.current;
        if (!container) return;

        // `?lang=` is set by the app from the active app language.
        const languageCode = new URLSearchParams(globalThis.location.search).get('lang') ?? 'en';

        const resolve = (message: FaceCaptureMessage) => {
            if (resolvedRef.current) return;
            resolvedRef.current = true;
            setOutcome(message);
            // Never include the component's captured frames here — the message
            // carries only the verdict and the transaction id.
            globalThis.window.YiviFace?.postMessage(JSON.stringify(message));
        };

        const onLiveness = (event: Event) => {
            const message = faceCaptureOutcome((event as CustomEvent).detail);
            // Lifecycle events (visibility, button presses) map to null and are
            // not an outcome.
            if (message) resolve(message);
        };

        let element: FaceLivenessWebComponent | null = null;
        let cancelled = false;

        const start = async () => {
            let faceApiUrl: string;
            try {
                const response = await fetch('/api/face-capture-config');
                if (!response.ok) {
                    throw new Error(`face capture config unavailable (HTTP ${response.status})`);
                }
                const config = await response.json();
                faceApiUrl = config.face_api_url;
                if (!faceApiUrl) {
                    throw new Error('face capture config has no face_api_url');
                }
            } catch (cause) {
                // Without a service URL the component would silently fall back to
                // Regula's own cloud, so fail loudly instead.
                const message = cause instanceof Error ? cause.message : 'face capture config unavailable';
                setError(message);
                resolve({ status: 'error', message });
                return;
            }

            if (cancelled) return;

            const settings: FaceLivenessSettings = {
                url: faceApiUrl,
                locale: languageCode,
                // Matches the native build's LivenessType.PASSIVE.
                livenessType: FaceLivenessType.PASSIVE,
                // The app shows its own intro screen before opening this page, and
                // pops the WebView the moment a result arrives, so the component's
                // own onboarding and success screens would only duplicate or flash.
                startScreen: false,
                finishScreen: false,
                // The app's own app-bar back button is the single way out; it
                // resolves as a cancel.
                closeDisabled: true,
                copyright: false,
                customization: yiviCustomization,
            };

            // The component's connectedCallback re-reads url/startScreen/etc. from
            // element *attributes* and writes them into its store, so settings
            // assigned before the element is attached are clobbered back to
            // defaults — for `url` that means silently falling back to Regula's
            // cloud Face API (https://faceapi.regulaforensics.com) instead of the
            // configured one. Per the package README, `settings` must be assigned
            // only after the element is in the DOM. Listener first so no early
            // event is missed.
            element = document.createElement('face-liveness') as FaceLivenessWebComponent;
            element.addEventListener('face-liveness', onLiveness);
            container.appendChild(element);
            element.settings = settings;
        };

        void start();

        return () => {
            cancelled = true;
            element?.removeEventListener('face-liveness', onLiveness);
            element?.remove();
        };
    }, []);

    return (
        <div id="container">
            <div ref={containerRef} style={{ flex: 1, minHeight: 0 }} />
            {error && <div className="warning">{error}</div>}
            {/* Only reachable outside the app: in the WebView the app pops this
                page as soon as the message is posted. */}
            {outcome && !globalThis.window.YiviFace && (
                <pre data-testid="face-capture-outcome">{JSON.stringify(outcome)}</pre>
            )}
        </div>
    );
}
