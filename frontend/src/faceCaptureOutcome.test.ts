import { describe, expect, it } from 'vitest';
import {
    ErrorTypes,
    FaceEventActions,
    FaceLivenessResultStatus,
    ResponseCode,
} from '@regulaforensics/vp-frontend-face-components';
import type { FaceLivenessDetailType, FaceLivenessResponseType } from '@regulaforensics/vp-frontend-face-components';
import { faceCaptureOutcome } from './faceCaptureOutcome';

/** A finished liveness response, with the fields this page does not read stubbed. */
function response(overrides: Partial<FaceLivenessResponseType> = {}): FaceLivenessResponseType {
    return {
        images: ['data:image/jpeg;base64,AAAA'],
        code: 0,
        metadata: {},
        estimatedAge: null,
        tag: 'yivi',
        status: FaceLivenessResultStatus.CONFIRMED,
        transactionId: 'txn-1',
        type: 1,
        ...overrides,
    };
}

function finished(overrides: Partial<FaceLivenessResponseType> = {}): FaceLivenessDetailType {
    return {
        action: FaceEventActions.PROCESS_FINISHED,
        data: { status: ResponseCode.OK, response: response(overrides) },
    };
}

describe('faceCaptureOutcome', () => {
    it('reports a confirmed liveness as passed with its transaction id', () => {
        expect(faceCaptureOutcome(finished())).toEqual({ status: 'passed', transactionId: 'txn-1' });
    });

    it('reports an unconfirmed liveness as failed but still forwards the id', () => {
        // The issuer, not this page, decides what an unconfirmed liveness means.
        expect(faceCaptureOutcome(finished({ status: FaceLivenessResultStatus.NOT_CONFIRMED }))).toEqual({
            status: 'failed',
            transactionId: 'txn-1',
        });
    });

    it('treats an unknown liveness verdict as failed', () => {
        expect(faceCaptureOutcome(finished({ status: FaceLivenessResultStatus.UNKNOWN }))).toEqual({
            status: 'failed',
            transactionId: 'txn-1',
        });
    });

    it('falls back to the transaction id reported outside the response', () => {
        const detail: FaceLivenessDetailType = {
            action: FaceEventActions.PROCESS_FINISHED,
            data: { status: ResponseCode.OK, transactionId: 'txn-outer' },
        };
        // No response means no CONFIRMED verdict, so this is not a live face.
        expect(faceCaptureOutcome(detail)).toEqual({ status: 'failed', transactionId: 'txn-outer' });
    });

    it('never leaks the captured frames into the message', () => {
        const message = faceCaptureOutcome(finished());
        expect(JSON.stringify(message)).not.toContain('base64');
    });

    it('maps a closed component to cancelled', () => {
        expect(faceCaptureOutcome({ action: FaceEventActions.CLOSE, data: null })).toEqual({
            status: 'cancelled',
        });
    });

    it('maps an errored session to error with the reported reason', () => {
        const detail: FaceLivenessDetailType = {
            action: FaceEventActions.PROCESS_FINISHED,
            data: { status: ResponseCode.ERROR, reason: ErrorTypes.CAMERA_PERMISSION_DENIED },
        };
        expect(faceCaptureOutcome(detail)).toEqual({
            status: 'error',
            message: ErrorTypes.CAMERA_PERMISSION_DENIED,
        });
    });

    it('maps an empty response to error', () => {
        const detail: FaceLivenessDetailType = {
            action: FaceEventActions.PROCESS_FINISHED,
            data: { status: ResponseCode.EMPTY },
        };
        expect(faceCaptureOutcome(detail)).toEqual({ status: 'error', message: 'liveness failed' });
    });

    it('maps an exhausted retry counter to error, not a forwardable verdict', () => {
        const outcome = faceCaptureOutcome({ action: FaceEventActions.RETRY_COUNTER_EXCEEDED, data: null });
        expect(outcome).toEqual({ status: 'error', message: 'liveness retry limit exceeded' });
    });

    it('ignores the component lifecycle events that are not an outcome', () => {
        const nonTerminal = [
            FaceEventActions.ELEMENT_VISIBLE,
            FaceEventActions.PRESS_START_BUTTON,
            FaceEventActions.PRESS_RETRY_BUTTON,
            FaceEventActions.SERVICE_INITIALIZED,
        ];
        for (const action of nonTerminal) {
            expect(faceCaptureOutcome({ action, data: null })).toBeNull();
        }
    });
});
