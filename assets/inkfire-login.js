// Foundation - Inkfire Login v2.2.2 - resilient, accessible login enhancements
(function () {
    'use strict';

    const IFLS = {
        init() {
            this.enhanceNotices();
            this.enhanceForms();
            this.assetErrorHandling();
            this.autoFocus();
            this.passwordStrength();
            this.responsiveChecks();

            // Self-healing: confirm the critical stylesheet has painted.
            window.setTimeout(() => this.checkCSS(), 1000);
        },

        fallback() {
            document.body.classList.remove('inkfire-login');
            document.querySelector('.if-full-bg')?.remove();
            console.warn('IFLS: Falling back to the default WordPress login');
        },

        enhanceNotices() {
            const notices = document.querySelectorAll(
                '.if-card #login_error, .if-card .error, .if-card .notice-error, .if-card .message, .if-card .success, .if-card .notice-info'
            );

            notices.forEach((notice) => {
                const isError = notice.id === 'login_error'
                    || notice.classList.contains('error')
                    || notice.classList.contains('notice-error');

                if (!notice.hasAttribute('role')) {
                    notice.setAttribute('role', isError ? 'alert' : 'status');
                }
                if (!notice.hasAttribute('aria-live')) {
                    notice.setAttribute('aria-live', isError ? 'assertive' : 'polite');
                }
                notice.setAttribute('aria-atomic', 'true');
            });

            const firstError = document.querySelector(
                '.if-card #login_error, .if-card .error, .if-card .notice-error'
            );

            if (firstError) {
                firstError.setAttribute('tabindex', '-1');
                window.setTimeout(() => firstError.focus({ preventScroll: true }), 120);
            }
        },

        enhanceForms() {
            document.querySelectorAll('.if-card input.input, .if-card select, .if-card textarea').forEach((input) => {
                const field = input.closest('p') || input.parentElement;

                input.addEventListener('focus', () => field?.classList.add('if-input-focused'));
                input.addEventListener('blur', () => {
                    if (!input.value) {
                        field?.classList.remove('if-input-focused');
                    }
                });

                input.addEventListener('invalid', () => {
                    input.setAttribute('aria-invalid', 'true');
                    field?.classList.add('if-input-invalid');
                });

                input.addEventListener('input', () => {
                    if (input.validity.valid) {
                        input.removeAttribute('aria-invalid');
                        field?.classList.remove('if-input-invalid');
                    }
                });
            });

            document.querySelectorAll('.if-card form').forEach((form) => {
                // The WordPress admin-email confirmation screen has a dedicated
                // server-side flow and intentionally receives no login JS.
                if (
                    form.id === 'if_confirm_email_form'
                    || form.querySelector('input[name="confirm_admin_email"]')
                ) {
                    return;
                }

                const submitButton = form.querySelector('input[type="submit"], button[type="submit"]');
                if (!submitButton) {
                    return;
                }

                const isInput = submitButton instanceof HTMLInputElement;
                const originalText = isInput ? submitButton.value : submitButton.textContent;

                const resetSubmissionState = () => {
                    delete form.dataset.iflsSubmitted;
                    form.removeAttribute('aria-busy');
                    submitButton.removeAttribute('aria-disabled');

                    if (isInput) {
                        submitButton.value = originalText;
                    } else {
                        submitButton.textContent = originalText;
                    }
                };

                form.addEventListener('submit', (event) => {
                    // Prevent an accidental second submission without disabling
                    // the submitter, so its name/value remains in the POST body.
                    if (form.dataset.iflsSubmitted === 'true') {
                        event.preventDefault();
                        return;
                    }

                    form.dataset.iflsSubmitted = 'true';
                    form.setAttribute('aria-busy', 'true');
                    submitButton.setAttribute('aria-disabled', 'true');

                    if (isInput) {
                        submitButton.value = 'Please wait…';
                    } else {
                        submitButton.textContent = 'Please wait…';
                    }

                    // Recovery for a blocked navigation or browser-side error.
                    window.setTimeout(resetSubmissionState, 30000);
                });
            });
        },

        assetErrorHandling() {
            document.addEventListener('error', (event) => {
                const target = event.target;
                if (!(target instanceof HTMLImageElement) || !target.src.includes('inkfire')) {
                    return;
                }

                this.reportAssetError(target.src, 'Failed to load');

                if (target.src.includes('cdn.inkfire.co.uk')) {
                    const pluginUrl = window.ifls_vars?.plugin_url || '';
                    target.src = target.src.replace(
                        'https://cdn.inkfire.co.uk/login/v2/',
                        `${pluginUrl}assets/`
                    );
                }
            }, true);
        },

        reportAssetError(asset, error) {
            if (typeof window.ifls_vars === 'undefined' || !window.ifls_vars?.ajax_url) {
                return;
            }

            const body = new URLSearchParams({
                action: 'ifls_asset_error',
                nonce: window.ifls_vars.nonce || '',
                asset,
                error
            });

            fetch(window.ifls_vars.ajax_url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
                body: body.toString(),
                credentials: 'same-origin'
            }).catch(() => { /* Diagnostics must never interrupt login. */ });
        },

        autoFocus() {
            const hasNotice = document.querySelector(
                '.if-card .error, .if-card #login_error, .if-card .notice-error, .if-card .message, .if-card .success'
            );
            const finePointer = window.matchMedia?.('(pointer: fine)').matches;
            const wideViewport = window.innerWidth >= 768;

            if (hasNotice || !finePointer || !wideViewport) {
                return;
            }

            const firstInput = document.querySelector(
                '.if-card input[type="text"], .if-card input[type="email"], .if-card input[type="password"]'
            );

            if (firstInput && this.isElementInViewport(firstInput)) {
                window.setTimeout(() => firstInput.focus({ preventScroll: true }), 250);
            }
        },

        passwordStrength() {
            const pass1 = document.getElementById('if_pass1');
            if (pass1 && pass1.dataset.strengthMeter === 'true') {
                this.initializeStrengthMeter(pass1);
            }
        },

        initializeStrengthMeter(input) {
            const wrapper = input.closest('.if-password-strength-wrapper');
            if (!wrapper || wrapper.querySelector('.if-password-strength-meter')) {
                return;
            }

            const meter = document.createElement('div');
            const textId = `${input.id || 'if-pass'}-strength-text`;
            meter.className = 'if-password-strength-meter';
            meter.setAttribute('role', 'progressbar');
            meter.setAttribute('aria-label', 'Password strength');
            meter.setAttribute('aria-valuemin', '0');
            meter.setAttribute('aria-valuemax', '5');
            meter.setAttribute('aria-valuenow', '0');
            meter.setAttribute('aria-valuetext', 'No password entered');
            meter.innerHTML = `<div class="strength-bar" aria-hidden="true"></div><div class="strength-text" id="${textId}" aria-live="polite"></div>`;
            wrapper.appendChild(meter);

            const existingDescription = input.getAttribute('aria-describedby');
            input.setAttribute(
                'aria-describedby',
                existingDescription ? `${existingDescription} ${textId}` : textId
            );

            input.addEventListener('input', () => {
                const strength = this.calculatePasswordStrength(input.value);
                this.updateStrengthMeter(meter, strength);
            });
        },

        calculatePasswordStrength(password) {
            let score = 0;
            if (!password) {
                return 0;
            }
            if (password.length > 7) score += 1;
            if (password.length > 11) score += 1;
            if (/[a-z]/.test(password)) score += 1;
            if (/[A-Z]/.test(password)) score += 1;
            if (/[0-9]/.test(password)) score += 1;
            if (/[^a-zA-Z0-9]/.test(password)) score += 1;
            return Math.min(score, 5);
        },

        updateStrengthMeter(meter, strength) {
            const bar = meter.querySelector('.strength-bar');
            const text = meter.querySelector('.strength-text');
            const levels = ['No password entered', 'Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
            const colors = ['#9da3ae', '#b42318', '#c25400', '#8a6500', '#287a37', '#13795b'];
            const label = levels[strength] || levels[0];

            meter.setAttribute('aria-valuenow', String(strength));
            meter.setAttribute('aria-valuetext', label);
            bar.style.width = `${(strength / 5) * 100}%`;
            bar.style.backgroundColor = colors[strength] || colors[0];
            text.textContent = strength === 0 ? '' : label;
        },

        responsiveChecks() {
            const checkViewport = () => {
                document.body.classList.toggle('if-mobile-tiny', window.innerWidth < 400);
                document.body.classList.toggle(
                    'if-foldable',
                    window.innerWidth < window.innerHeight && window.innerWidth < 540
                );
            };

            checkViewport();
            window.addEventListener('resize', checkViewport, { passive: true });
            window.addEventListener('orientationchange', checkViewport, { passive: true });
        },

        checkCSS() {
            const testElement = document.querySelector('.if-card');
            if (!testElement) {
                return;
            }

            const styles = window.getComputedStyle(testElement);
            const missingLayout = styles.display !== 'flex';
            const missingSurface = styles.backgroundColor === 'rgba(0, 0, 0, 0)'
                || styles.backgroundColor === 'transparent';

            if (missingLayout || missingSurface) {
                console.warn('IFLS: CSS may not have loaded, injecting an accessible fallback');
                this.injectFallbackCSS();
            }
        },

        injectFallbackCSS() {
            const fallback = `
                body.login { margin: 0; background: #151622; color: #f2f2f2; }
                .if-full-bg { min-height: 100vh; padding: 20px; background: #151622; }
                .if-shell { display: grid; grid-template-columns: minmax(280px, .8fr) minmax(0, 1.4fr); width: min(1100px, 100%); margin: auto; border: 1px solid #d9dbe3; border-radius: 28px; overflow: hidden; }
                .if-left { display: flex; flex-direction: column; padding: 24px; background: #1a1c29; color: #f2f2f2; }
                .if-left-content { display: flex; flex: 1 1 auto; flex-direction: column; justify-content: center; }
                .if-right { display: flex; flex-direction: column; background: #151622; color: #f2f2f2; }
                .if-logo-wrap { display: flex; justify-content: center; padding: 40px 24px 18px; }
                .if-logo { width: min(300px, 80%); height: auto; }
                .if-teal { display: flex; flex-direction: column; gap: 16px; padding: 0 28px 36px; }
                .if-heading-wrap { display: flex; justify-content: center; }
                .if-card-title { margin: 0; padding: 9px 18px; color: #151622; background: #fbccbf; border-radius: 999px; text-align: center; }
                .if-card { display: flex; flex-direction: column; background-color: #1e4e47; color: #f2f2f2; padding: 28px; border: 1px solid #d9dbe3; border-radius: 22px; }
                .if-card .message, .if-card .success, .if-card .error, .if-card #login_error, .if-card .notice { padding: 16px 18px; color: #fff; background: #a76030; border: 1px solid #e27200; border-radius: 18px; }
                .if-card input.input { width: 100%; min-height: 48px; padding: 12px; margin-bottom: 15px; background: #fff; color: #151622; }
                .if-card .button-primary { min-height: 48px; padding: 11px 20px; background: #fbccbf; color: #151622; border: 0; border-radius: 999px; }
                .if-language-row { display: flex; justify-content: center; margin-top: 14px; }
                .if-lang-left { width: min(100%, 330px); }
                .if-lang-left #if-language-switcher { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 9px; }
                @media (max-width: 760px) { .if-shell { grid-template-columns: 1fr; } .if-right { order: -1; } .if-teal { padding-inline: 14px; } }
            `;
            const style = document.createElement('style');
            style.dataset.iflsFallback = 'true';
            style.textContent = fallback;
            document.head.appendChild(style);
        },

        isElementInViewport(element) {
            const rect = element.getBoundingClientRect();
            return (
                rect.top >= 0
                && rect.left >= 0
                && rect.bottom <= (window.innerHeight || document.documentElement.clientHeight)
                && rect.right <= (window.innerWidth || document.documentElement.clientWidth)
            );
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => IFLS.init());
    } else {
        IFLS.init();
    }

    window.IFLS_fallback = IFLS.fallback;
}());
