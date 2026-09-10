"""Tests hash-matched source files. Runs locally; never submits real credentials."""
import json, hashlib, os, tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
B=Path(__file__).resolve().parents[1]
OUTPUT=Path(os.environ.get('IFLS_TEST_OUTPUT', tempfile.mkdtemp(prefix='ifls-login-tests-')))
OUTPUT.mkdir(parents=True, exist_ok=True)
current=(B/'assets/inkfire-login.js').read_text()
assert hashlib.sha256(current.encode()).hexdigest()=='160afc3ad1e716bc5bcaab7b1c4db63001a818a484fd0c18fa39bfc9e10421d2'
original=current
reversals=[
("    // A cache optimizer may replay ready events or execute this asset again.\n    // Login enhancements must bind once, never cancel their own first submit.\n    if (window.IFLS_login_enhancements_loaded) {\n        return;\n    }\n    window.IFLS_login_enhancements_loaded = true;\n    let initialized = false;\n\n",''),
("            if (initialized) {\n                return;\n            }\n            initialized = true;\n",''),
("                let recoveryTimer = null;\n",''),
("                    window.clearTimeout(recoveryTimer);\n                    recoveryTimer = null;\n",''),
("                window.addEventListener('pageshow', (event) => {\n                    if (event.persisted) {\n                        resetSubmissionState();\n                    }\n                });\n\n",''),
("                    // Respect a validator that has already stopped this request.\n                    if (event.defaultPrevented) {\n                        return;\n                    }\n",''),
("                    recoveryTimer = window.setTimeout(resetSubmissionState, 30000);\n                    // A later security/validation handler may cancel the same\n                    // event. Restore the UI, but never resubmit credentials.\n                    window.setTimeout(() => {\n                        if (event.defaultPrevented) {\n                            resetSubmissionState();\n                        }\n                    }, 0);",'                    window.setTimeout(resetSubmissionState, 30000);'),
("document.addEventListener('DOMContentLoaded', () => IFLS.init(), { once: true });", "document.addEventListener('DOMContentLoaded', () => IFLS.init());")]
for a,b in reversals:
    assert original.count(a)==1,a
    original=original.replace(a,b)
assert hashlib.sha256(original.encode()).hexdigest()=='91bbbd73af675e6789588c02d6b34731f8c7e6e46cd5ef0f06a6b95b5f9c52f4'
# The baseline is reconstructed in memory; no production files are written.
FORM='''<div class="if-card" style="display:flex;background:#1c1d2d;padding:30px;"><form id="if_card_loginform" action="https://inkfire.co.uk/wp-login.php" method="post"><p><label for="if_user_login">Username or Email</label><input name="log" id="if_user_login" class="input" autocomplete="username"></p><p><label for="if_user_pass">Password</label><input type="password" name="pwd" id="if_user_pass" class="input" autocomplete="current-password"></p><p><input type="checkbox" name="rememberme" id="if_rememberme" value="forever"><label for="if_rememberme">Remember Me</label></p><input type="submit" id="if_wp_submit" name="wp-submit" value="Log In"><input type="hidden" name="redirect_to" value="https://inkfire.co.uk/wp-admin/"><input type="hidden" name="testcookie" value="1"><input type="hidden" name="ifls_login_form" value="inline"><input name="ifls_login_website" value="" tabindex="-1" style="position:absolute;left:-9999px"></form></div>'''
FIXTURE='<!doctype html><html lang="en-GB"><meta name="viewport" content="width=device-width"><body>'+FORM+'</body></html>'
CASES=['fresh-mouse','fresh-keyboard','mobile-click','duplicate-asset-late','duplicate-asset-before-ready','ready-event-replayed','cancelled-before','cancelled-after','back-forward-restore','genuine-double-submit','timeout-recovery','admin-email-untouched']
results=[]
with sync_playwright() as p:
    browser_path=os.environ.get('CHROMIUM_PATH')
    if not browser_path and Path('/usr/bin/chromium').exists(): browser_path='/usr/bin/chromium'
    browser=p.chromium.launch(headless=True,**({'executable_path':browser_path} if browser_path else {}))
    for version,source in [('original',original),('current',current)]:
        for scenario in CASES:
            errors=[]
            page=browser.new_page(viewport={'width':390 if scenario=='mobile-click' else 1280,'height':800})
            page.route('**/*',lambda route:route.abort())
            page.on('pageerror',lambda e: errors.append(str(e)))
            if scenario in ['duplicate-asset-before-ready','ready-event-replayed']:
                html=FIXTURE.replace('</body>','<script>'+source+'</script>'+('<script>'+source+'</script>' if scenario=='duplicate-asset-before-ready' else '')+'</body>')
                page.set_content(html)
                if scenario=='ready-event-replayed':page.evaluate("document.dispatchEvent(new Event('DOMContentLoaded'))")
            else:
                page.set_content(FIXTURE)
                if scenario=='cancelled-before':page.evaluate("document.querySelector('form').addEventListener('submit',e=>e.preventDefault())")
                if scenario=='admin-email-untouched':page.evaluate("document.querySelector('form').id='if_confirm_email_form'")
                page.add_script_tag(content=source)
                if scenario=='duplicate-asset-late':page.add_script_tag(content=source)
            page.wait_for_timeout(300)
            if scenario=='cancelled-after':page.evaluate("document.querySelector('form').addEventListener('submit',e=>e.preventDefault())")
            if scenario=='timeout-recovery':page.evaluate("window.__recovery=[];let nativeTimeout=window.setTimeout;window.setTimeout=(fn,ms)=>ms===30000?(window.__recovery.push(fn),1):nativeTimeout(fn,ms)")
            payloadOK=True
            if scenario.startswith('fresh-') or scenario=='mobile-click':
                page.locator('#if_user_login').fill('local-test')
                page.locator('#if_user_pass').fill('LocalDummyOnly!')
                page.locator('#if_rememberme').check()
                page.evaluate("window.__submitted=[];document.addEventListener('submit',event=>{window.__submitted.push({allowed:!event.defaultPrevented,data:Object.fromEntries(new FormData(event.target,event.submitter))});event.preventDefault()})")
                if scenario=='fresh-keyboard':page.locator('#if_user_pass').press('Enter')
                else:page.locator('#if_wp_submit').click()
                event=page.evaluate('window.__submitted[0]')
                allowed=event['allowed'];data=event['data']
                payloadOK=(data.get('log')=='local-test' and data.get('pwd')=='LocalDummyOnly!' and data.get('rememberme')=='forever' and data.get('testcookie')=='1' and data.get('ifls_login_form')=='inline' and data.get('ifls_login_website')=='' and data.get('redirect_to')=='https://inkfire.co.uk/wp-admin/' and 'wp-submit' in data)
            else:
                allowed=page.evaluate("document.querySelector('form').dispatchEvent(new SubmitEvent('submit',{bubbles:true,cancelable:true,submitter:document.querySelector('[type=submit]')}))")
            if scenario=='back-forward-restore':page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}))")
            if scenario=='genuine-double-submit':second=page.evaluate("document.querySelector('form').dispatchEvent(new SubmitEvent('submit',{bubbles:true,cancelable:true}))")
            if scenario=='timeout-recovery':page.evaluate("window.__recovery[0]()")
            page.wait_for_timeout(20)
            state=page.evaluate("({busy:document.querySelector('form').getAttribute('aria-busy'),label:document.querySelector('[type=submit]').value,disabled:document.querySelector('[type=submit]').disabled})")
            if scenario in ['cancelled-before','cancelled-after','back-forward-restore','timeout-recovery','admin-email-untouched']:
                passed=state['busy'] is None and state['label']=='Log In'
            elif scenario=='genuine-double-submit':passed=allowed and not second and state['busy']=='true'
            else:passed=allowed and payloadOK
            results.append({'version':version,'case':scenario,'passed':bool(passed and not state['disabled'] and not errors),'submit_allowed':allowed,'errors':errors,**state})
            page.close()
    browser.close()
report={'environment':'Local Chromium; release source hash matches the inspected live fix; minimal form fixture uses observed input attributes, not full page styling; submit events/FormData inspected with no external POST; pageshow and timeout simulated; no real sign-in','original_sha256':hashlib.sha256(original.encode()).hexdigest(),'current_sha256':hashlib.sha256(current.encode()).hexdigest(),'summary':{v:{'passed':sum(r['passed'] for r in results if r['version']==v),'total':len(CASES)} for v in ['original','current']},'results':results}
(OUTPUT/'login-ui-regression.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
assert all(r['passed'] for r in results if r['version']=='current')
