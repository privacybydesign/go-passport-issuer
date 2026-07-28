import {
    FaceEventActions,
    FaceLivenessResultStatus,
    ResponseCode,
} from '@regulaforensics/vp-frontend-face-components';
import type { FaceLivenessDetailType } from '@regulaforensics/vp-frontend-face-components';

/**
 * A message the capture page posts to the Yivi app over the WebView's `YiviFace`
 * JavaScript channel.
 *
 * The app parses exactly these four statuses (see
 * `yivi_fdroid/lib/face_liveness_message.dart` in irmamobile):
 * - `passed` / `failed` — liveness ran to completion; `transactionId` is
 *   forwarded to the issuer, which decides whether the face matches the chip
 *   portrait. `failed` still carries the id so the issuer, not this page, makes
 *   the call.
 * - `cancelled` / `error` — the app throws and lands on its generic issuance
 *   error screen.
 */
export type FaceCaptureMessage =
    | { status: 'passed' | 'failed'; transactionId?: string }
    | { status: 'cancelled' }
    | { status: 'error'; message?: string };

/**
 * Maps one `face-liveness` event from Regula's web component to the message for
 * the app, or `null` when the event is not a terminal outcome (the component
 * also reports element visibility, button presses and service initialisation,
 * which the app has no interest in).
 *
 * Privacy: a finished session also exposes the raw selfie frames on
 * `data.response.images`. This function reads only the liveness verdict and the
 * transaction id, and nothing here — or in its callers — may log, store or
 * transmit `images` anywhere. The frames the Face API needs were already sent by
 * the component itself.
 */
export function faceCaptureOutcome(detail: FaceLivenessDetailType): FaceCaptureMessage | null {
    const { action, data } = detail;

    if (action === FaceEventActions.CLOSE) {
        return { status: 'cancelled' };
    }

    // The component gives up after settings.retryCount attempts. The user did
    // not pass liveness and there is no transaction to forward, so this is an
    // error rather than a `failed` verdict the issuer could act on.
    if (action === FaceEventActions.RETRY_COUNTER_EXCEEDED) {
        return { status: 'error', message: 'liveness retry limit exceeded' };
    }

    if (action !== FaceEventActions.PROCESS_FINISHED) {
        return null;
    }

    if (!data || data.status !== ResponseCode.OK) {
        return { status: 'error', message: data?.reason ?? 'liveness failed' };
    }

    // The id lives on the response, but the component also surfaces it one level
    // up; prefer the response and fall back so a session is never dropped just
    // because of where the id was reported.
    const transactionId = data.response?.transactionId ?? data.transactionId;

    // Anything other than CONFIRMED (NOT_CONFIRMED, UNKNOWN, or a response the
    // component finished without) is not a live face.
    const isLive = data.response?.status === FaceLivenessResultStatus.CONFIRMED;

    return { status: isLive ? 'passed' : 'failed', transactionId };
}
