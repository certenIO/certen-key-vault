/**
 * Certen Key Vault - Sign Request Queue
 *
 * Manages pending signature requests that require user approval.
 */

import { SignRequest, SignRequestStatus, SignRequestData } from '../shared/types';
import { generateUUID } from '../vault/crypto';

// =============================================================================
// Types
// =============================================================================

interface RequestCallbacks {
  onComplete: (result: unknown, error?: string) => void;
}

// =============================================================================
// SignRequestQueue Class
// =============================================================================

export class SignRequestQueue {
  private requests: Map<string, SignRequest> = new Map();
  private callbacks: Map<string, RequestCallbacks> = new Map();

  /**
   * Adds a new sign request to the queue.
   *
   * @param type - Request type
   * @param data - Request data
   * @param origin - Requesting website origin
   * @returns Request ID
   */
  add(
    type: SignRequest['type'],
    data: SignRequestData,
    origin: string
  ): string {
    const id = generateUUID();

    const request: SignRequest = {
      id,
      type,
      origin,
      timestamp: Date.now(),
      data,
      status: 'pending'
    };

    this.requests.set(id, request);
    return id;
  }

  /**
   * Gets a request by ID.
   */
  get(requestId: string): SignRequest | undefined {
    return this.requests.get(requestId);
  }

  /**
   * Gets the next pending request.
   */
  getNext(): SignRequest | undefined {
    for (const request of this.requests.values()) {
      if (request.status === 'pending') {
        return request;
      }
    }
    return undefined;
  }

  /**
   * Gets all pending requests.
   */
  getPending(): SignRequest[] {
    return Array.from(this.requests.values())
      .filter(r => r.status === 'pending')
      .sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Gets the count of pending requests.
   */
  getPendingCount(): number {
    return Array.from(this.requests.values())
      .filter(r => r.status === 'pending')
      .length;
  }

  /**
   * Updates request status.
   */
  updateStatus(requestId: string, status: SignRequestStatus): void {
    const request = this.requests.get(requestId);
    if (request) {
      request.status = status;
    }
  }

  /**
   * Registers a callback to be called when the request completes.
   */
  onComplete(
    requestId: string,
    callback: (result: unknown, error?: string) => void
  ): void {
    this.callbacks.set(requestId, { onComplete: callback });
  }

  /**
   * Completes a request successfully with a result.
   */
  complete(requestId: string, result: unknown): void {
    const request = this.requests.get(requestId);
    if (request) {
      request.status = 'completed';
    }

    const callbacks = this.callbacks.get(requestId);
    if (callbacks) {
      callbacks.onComplete(result);
      this.callbacks.delete(requestId);
    }

    // Clean up completed request after a delay
    setTimeout(() => {
      this.requests.delete(requestId);
    }, 5000);
  }

  /**
   * Rejects a request with an error.
   */
  reject(requestId: string, reason: string): void {
    const request = this.requests.get(requestId);
    if (request) {
      request.status = 'rejected';
    }

    const callbacks = this.callbacks.get(requestId);
    if (callbacks) {
      callbacks.onComplete(undefined, reason);
      this.callbacks.delete(requestId);
    }

    // Clean up rejected request after a delay
    setTimeout(() => {
      this.requests.delete(requestId);
    }, 5000);
  }

  /**
   * Marks a request as errored.
   */
  error(requestId: string, errorMessage: string): void {
    const request = this.requests.get(requestId);
    if (request) {
      request.status = 'error';
    }

    const callbacks = this.callbacks.get(requestId);
    if (callbacks) {
      callbacks.onComplete(undefined, errorMessage);
      this.callbacks.delete(requestId);
    }

    setTimeout(() => {
      this.requests.delete(requestId);
    }, 5000);
  }

  /**
   * Removes a request from the queue.
   */
  remove(requestId: string): void {
    this.requests.delete(requestId);
    this.callbacks.delete(requestId);
  }

  /**
   * Clears all requests.
   */
  clear(): void {
    // Reject all pending requests
    for (const [id, request] of this.requests) {
      if (request.status === 'pending') {
        this.reject(id, 'Queue cleared');
      }
    }
    this.requests.clear();
    this.callbacks.clear();
  }

  /**
   * Cleans up old requests (older than timeout).
   */
  cleanup(timeoutMs: number = 300000): void {
    const now = Date.now();
    for (const [id, request] of this.requests) {
      if (now - request.timestamp > timeoutMs) {
        if (request.status === 'pending') {
          this.reject(id, 'Request timeout');
        } else {
          this.requests.delete(id);
          this.callbacks.delete(id);
        }
      }
    }
  }
}

// =============================================================================
// Singleton Instance
// =============================================================================

export const signRequestQueue = new SignRequestQueue();
