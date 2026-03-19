const DeviceFingerprint = {
    // ===== SECURITY FIX: Check for user consent =====
    hasConsent: function() {
        const consent = localStorage.getItem('fsc_fingerprint_consent');
        return consent === 'true';
    },

    // ===== SECURITY FIX: Request user consent =====
    requestConsent: async function() {
        if (this.hasConsent()) return true;

        return new Promise((resolve) => {
            // Create consent overlay
            const overlay = document.createElement('div');
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.9);
                backdrop-filter: blur(10px);
                z-index: 20000;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: 'Inter', sans-serif;
            `;

            const modal = document.createElement('div');
            modal.style.cssText = `
                background: var(--freedom-bg-secondary);
                border: 1px solid var(--freedom-border);
                border-radius: 28px;
                padding: 32px;
                max-width: 450px;
                width: 90%;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                text-align: center;
            `;

            modal.innerHTML = `
                <h2 style="color: var(--freedom-teal-light); margin-bottom: 20px; font-size: 22px;">🔐 Privacy Option</h2>
                <p style="color: var(--freedom-text-secondary); margin-bottom: 20px; font-size: 15px; line-height: 1.6;">
                    To help prevent abuse, we can optionally use device fingerprinting. This creates a unique identifier based on your browser's characteristics.
                </p>
                <p style="color: var(--freedom-text-muted); margin-bottom: 25px; font-size: 13px;">
                    You can choose to opt out - you'll still be able to use the service with a session-based ID.
                </p>
                <div style="display: flex; gap: 15px; justify-content: center;">
                    <button id="consentAccept" style="padding: 12px 25px; background: linear-gradient(135deg, var(--freedom-deep-teal), var(--freedom-teal-light)); border: none; color: white; border-radius: 30px; cursor: pointer; font-weight: 500;">✅ Accept</button>
                    <button id="consentDecline" style="padding: 12px 25px; background: var(--freedom-bg-tertiary); border: 1px solid var(--freedom-border); color: var(--freedom-text-secondary); border-radius: 30px; cursor: pointer; font-weight: 500;">🔷 Opt Out</button>
                </div>
            `;

            overlay.appendChild(modal);
            document.body.appendChild(overlay);

            document.getElementById('consentAccept').onclick = () => {
                localStorage.setItem('fsc_fingerprint_consent', 'true');
                document.body.removeChild(overlay);
                resolve(true);
            };

            document.getElementById('consentDecline').onclick = () => {
                localStorage.setItem('fsc_fingerprint_consent', 'false');
                document.body.removeChild(overlay);
                resolve(false);
            };
        });
    },

    // Generate fingerprint (only used if consented)
    generateFingerprint: function() {
        const screenData = `${screen.width}x${screen.height}x${screen.colorDepth}`;
        const timeData = new Date().getTimezoneOffset();
        const languageData = navigator.language || navigator.userLanguage;
        const hardwareData = navigator.hardwareConcurrency || 'unknown';
        const platformData = navigator.platform || 'unknown';

        // Canvas fingerprinting
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = "top";
        ctx.font = "14px 'Arial'";
        ctx.fillStyle = "#f60";
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = "#069";
        ctx.fillText("FSC™", 2, 15);
        const canvasData = canvas.toDataURL();

        // WebGL fingerprinting
        let webglData = 'no-webgl';
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    webglData = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                }
            }
        } catch (e) {
            webglData = 'webgl-error';
        }

        const fingerprintData = [
            screenData,
            timeData,
            languageData,
            hardwareData,
            platformData,
            canvasData,
            webglData,
            navigator.userAgent
        ].join('|');

        return this.hashString(fingerprintData);
    },

    hashString: function(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16).padStart(8, '0');
    },

    // ===== SECURITY FIX: Get device ID with consent =====
    getDeviceId: function() {
        return new Promise(async (resolve, reject) => {
            try {
                // Check for consent
                const consented = await this.requestConsent();

                if (!consented) {
                    // User opted out - generate session-only ID
                    const sessionId = 'session_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
                    console.log('🔷 User opted out of fingerprinting, using session ID');
                    resolve(sessionId);
                    return;
                }

                // User consented - use IndexedDB for persistent storage
                const request = indexedDB.open('FSC_DeviceDB', 1);

                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    if (!db.objectStoreNames.contains('device')) {
                        db.createObjectStore('device');
                    }
                };

                request.onsuccess = (event) => {
                    const db = event.target.result;
                    const transaction = db.transaction(['device'], 'readwrite');
                    const store = transaction.objectStore('device');

                    const getRequest = store.get('deviceId');

                    getRequest.onsuccess = () => {
                        let deviceId = getRequest.result;

                        if (!deviceId) {
                            deviceId = this.generateFingerprint();
                            store.put(deviceId, 'deviceId');
                            console.log('✅ New device fingerprint created with consent');
                        } else {
                            console.log('✅ Existing device fingerprint loaded');
                        }

                        resolve(deviceId);
                    };

                    getRequest.onerror = () => {
                        // Fallback to localStorage
                        let deviceId = localStorage.getItem('fsc_device_id');
                        if (!deviceId) {
                            deviceId = this.generateFingerprint();
                            localStorage.setItem('fsc_device_id', deviceId);
                        }
                        resolve(deviceId);
                    };
                };

                request.onerror = () => {
                    // Fallback to localStorage
                    let deviceId = localStorage.getItem('fsc_device_id');
                    if (!deviceId) {
                        deviceId = this.generateFingerprint();
                        localStorage.setItem('fsc_device_id', deviceId);
                    }
                    resolve(deviceId);
                };
            } catch (error) {
                console.error('Error in getDeviceId:', error);
                // Fallback to session ID on error
                resolve('session_' + Math.random().toString(36).substring(2));
            }
        });
    },

    // Clear device ID (for testing)
    clearDeviceId: function() {
        return new Promise((resolve) => {
            const request = indexedDB.open('FSC_DeviceDB', 1);

            request.onsuccess = (event) => {
                const db = event.target.result;
                const transaction = db.transaction(['device'], 'readwrite');
                const store = transaction.objectStore('device');
                store.delete('deviceId');
                localStorage.removeItem('fsc_device_id');
                localStorage.removeItem('fsc_fingerprint_consent');
                console.log('🗑️ Device ID and consent cleared');
                resolve();
            };

            request.onerror = () => {
                localStorage.removeItem('fsc_device_id');
                localStorage.removeItem('fsc_fingerprint_consent');
                resolve();
            };
        });
    }
};

// Auto-initialize
if (typeof window !== 'undefined') {
    window.DeviceFingerprint = DeviceFingerprint;
}