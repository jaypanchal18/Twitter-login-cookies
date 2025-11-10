"""
Twitter/X Login using Requests Library (Hybrid Approach)

This script uses minimal browser automation (Selenium) ONLY to extract the initial flow token,
then uses pure requests library for all subsequent API calls. This approach minimizes browser
usage while working around Twitter's JavaScript-based flow token generation.

The script is "mostly requests" - browser automation is only used for the initial token extraction.
"""

import argparse
import time
import pprint
import requests
import re
import json
from urllib.parse import urlparse, parse_qs

# Optional: Only import Selenium if needed for token extraction
try:
    import undetected_chromedriver as uc
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        SELENIUM_AVAILABLE = True
    except ImportError:
        SELENIUM_AVAILABLE = False


MAIN_PAGE = "https://x.com/"
LOGIN_PAGE = "https://x.com/i/flow/login"
API_BASE = "https://x.com/i/api/1.1"


def extract_flow_token_with_browser(verbose=False):
    """
    Use minimal browser automation to extract flow token from Twitter's login page.
    This is the ONLY place we use browser automation - everything else uses requests.
    
    Returns:
        tuple: (flow_token, cookies_dict) or (None, {})
    """
    if not SELENIUM_AVAILABLE:
        if verbose:
            print("[!] Selenium not available. Cannot extract flow token.")
        return None, {}
    
    if verbose:
        print("[*] Using minimal browser automation to extract flow token...")
    
    driver = None
    try:
        # Use undetected-chromedriver if available (better anti-detection)
        # Note: Not using headless mode as it may cause issues with Twitter's detection
        try:
            options = uc.ChromeOptions()
            # Don't use headless - Twitter may detect it
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-blink-features=AutomationControlled')
            
            # Try creating driver - if it fails, try without version_main
            try:
                driver = uc.Chrome(options=options, version_main=None)
            except Exception as e1:
                if verbose:
                    print(f"[!] First attempt failed: {e1}")
                try:
                    driver = uc.Chrome(options=options)
                except Exception as e2:
                    if verbose:
                        print(f"[!] Alternative initialization also failed: {e2}")
                    raise e2
            
            # Wait a moment for browser to stabilize
            time.sleep(3)
            
            # Verify browser is still open
            try:
                current_url_check = driver.current_url
                if verbose:
                    print("[*] Browser window is open and accessible")
            except Exception as e:
                if verbose:
                    print(f"[!] Browser window closed immediately: {e}")
                try:
                    driver.quit()
                except:
                    pass
                raise Exception("Browser window closed immediately after launch")
            
        except Exception as e:
            if verbose:
                print(f"[!] Undetected Chrome failed: {e}, trying regular Chrome...")
            # Fallback to regular Chrome
            from selenium.webdriver.chrome.options import Options
            chrome_options = Options()
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            driver = webdriver.Chrome(options=chrome_options)
            time.sleep(3)
        
        if verbose:
            print(f"[*] Navigating to: {LOGIN_PAGE}")
        driver.get(LOGIN_PAGE)
        
        # Wait for page to load
        time.sleep(5)
        
        # Verify we're still connected
        try:
            current_url = driver.current_url
            if verbose:
                print(f"[*] Current URL: {current_url}")
        except Exception as e:
            if verbose:
                print(f"[!] Browser disconnected: {e}")
            raise Exception("Browser disconnected during navigation")
        
        # Wait for page to fully load and JavaScript to execute
        time.sleep(5)
        
        # Enable network logging to capture API responses
        try:
            driver.execute_cdp_cmd('Network.enable', {})
            driver.execute_cdp_cmd('Performance.enable', {})
        except:
            pass
        
        # Wait for login form to be ready
        username_input = None
        try:
            username_input = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'input[autocomplete="username"], input[name="text"]'))
            )
            if verbose:
                print("[*] Login form detected")
        except:
            if verbose:
                print("[!] Could not find login form")
        
        # Try entering a dummy username to trigger flow token generation
        # This is necessary because Twitter only generates flow tokens after user interaction
        if username_input:
            try:
                if verbose:
                    print("[*] Triggering flow token generation by entering dummy username...")
                username_input.clear()
                username_input.send_keys("dummy_trigger")
                time.sleep(1)
                # Press Enter or find Next button to trigger API call
                try:
                    next_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Next')]")
                    if next_button:
                        next_button.click()
                        if verbose:
                            print("[*] Clicked Next to trigger flow token generation")
                except:
                    username_input.send_keys("\n")
                time.sleep(3)  # Wait for API call to complete
            except Exception as e:
                if verbose:
                    print(f"[!] Error triggering flow token: {e}")
        
        # Wait for JavaScript to fully execute
        time.sleep(2)
        
        # Extract flow token from page source or JavaScript variables
        page_source = driver.page_source
        
        # Try multiple patterns to find flow token in page source
        patterns = [
            r'"flowToken":"([^"]+)"',
            r'flowToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'"flow_token":"([^"]+)"',
            r'flow_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'flowToken=([^&\s"\']+)',
        ]
        
        flow_token = None
        for pattern in patterns:
            match = re.search(pattern, page_source)
            if match:
                flow_token = match.group(1)
                if len(flow_token) > 20:  # Flow tokens are usually long
                    break
        
        # Also try executing JavaScript to get flow token from various locations
        if not flow_token:
            try:
                # Try multiple JavaScript approaches
                js_scripts = [
                    # Check window.__INITIAL_STATE__
                    """
                    if (window.__INITIAL_STATE__ && window.__INITIAL_STATE__.flow && window.__INITIAL_STATE__.flow.flowToken) {
                        return window.__INITIAL_STATE__.flow.flowToken;
                    }
                    return null;
                    """,
                    # Check window.__NEXT_DATA__
                    """
                    if (window.__NEXT_DATA__ && window.__NEXT_DATA__.props && window.__NEXT_DATA__.props.pageProps && window.__NEXT_DATA__.props.pageProps.flowToken) {
                        return window.__NEXT_DATA__.props.pageProps.flowToken;
                    }
                    return null;
                    """,
                    # Check for flow token in React state
                    """
                    try {
                        var reactRoot = document.querySelector('#react-root');
                        if (reactRoot && reactRoot._reactInternalInstance) {
                            var fiber = reactRoot._reactInternalInstance.current;
                            while (fiber) {
                                if (fiber.memoizedState && fiber.memoizedState.flowToken) {
                                    return fiber.memoizedState.flowToken;
                                }
                                fiber = fiber.return;
                            }
                        }
                    } catch(e) {}
                    return null;
                    """,
                    # Check localStorage/sessionStorage
                    """
                    try {
                        var stored = localStorage.getItem('flowToken') || sessionStorage.getItem('flowToken');
                        if (stored) return stored;
                    } catch(e) {}
                    return null;
                    """,
                    # Check for flow token in script tags
                    """
                    try {
                        var scripts = document.getElementsByTagName('script');
                        for (var i = 0; i < scripts.length; i++) {
                            var content = scripts[i].innerHTML;
                            var match = content.match(/"flowToken":"([^"]+)"/);
                            if (match) return match[1];
                        }
                    } catch(e) {}
                    return null;
                    """
                ]
                
                for js_script in js_scripts:
                    try:
                        token = driver.execute_script(js_script)
                        if token and len(str(token)) > 20:
                            flow_token = token
                            break
                    except:
                        continue
            except Exception as e:
                if verbose:
                    print(f"[!] JavaScript execution error: {e}")
        
        # Try to get flow token from network requests by monitoring API calls
        if not flow_token:
            try:
                if verbose:
                    print("[*] Monitoring network requests for flow token...")
                
                # Wait for any API calls to happen
                time.sleep(5)
                
                # Check network logs for API responses containing flow_token
                try:
                    logs = driver.get_log('performance')
                    for log in logs:
                        try:
                            message = json.loads(log['message'])
                            method = message.get('message', {}).get('method', '')
                            
                            if method == 'Network.responseReceived':
                                url = message.get('message', {}).get('params', {}).get('response', {}).get('url', '')
                                if 'onboarding' in url or 'task.json' in url or 'flow' in url.lower():
                                    request_id = message.get('message', {}).get('params', {}).get('requestId')
                                    if request_id:
                                        try:
                                            response_body = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                                            if response_body and 'body' in response_body:
                                                body_text = response_body['body']
                                                # Try to decode if base64
                                                if response_body.get('base64Encoded'):
                                                    import base64
                                                    body_text = base64.b64decode(body_text).decode('utf-8')
                                                
                                                # Look for flow_token in response
                                                if 'flow_token' in body_text or 'flowToken' in body_text:
                                                    match = re.search(r'["\']flow_token["\']\s*:\s*["\']([^"\']+)["\']', body_text)
                                                    if not match:
                                                        match = re.search(r'["\']flowToken["\']\s*:\s*["\']([^"\']+)["\']', body_text)
                                                    if match:
                                                        flow_token = match.group(1)
                                                        if verbose:
                                                            print(f"[*] Found flow token in network response!")
                                                        break
                                        except Exception as e:
                                            if verbose:
                                                print(f"[!] Error reading response body: {e}")
                                            continue
                        except:
                            continue
                except Exception as e:
                    if verbose:
                        print(f"[!] Error reading network logs: {e}")
            except:
                pass
        
        # Get cookies from browser
        cookies_dict = {}
        for cookie in driver.get_cookies():
            cookies_dict[cookie['name']] = cookie['value']
        
        if verbose:
            if flow_token:
                print(f"[*] Successfully extracted flow token: {flow_token[:30]}...")
            else:
                print("[!] Could not extract flow token from page")
        
        return flow_token, cookies_dict
        
    except Exception as e:
        if verbose:
            print(f"[!] Error extracting flow token: {e}")
        return None, {}
    finally:
        if driver:
            driver.quit()


def try_login_requests(email_or_username, password, verbose=False, verification_email=None, use_browser_for_token=True):
    """
    Login to Twitter/X using requests library (with minimal browser automation for token extraction).
    
    Args:
        email_or_username: Email or username
        password: Password
        verbose: Print debug information
        verification_email: Optional email address for verification when Twitter requires it
        use_browser_for_token: If True, use browser to extract flow token (default: True)
    
    Returns:
        dict with 'ok', 'cookies', 'reason', 'url'
    """
    result = {
        "ok": False,
        "cookies": {},
        "reason": None,
        "url": None,
    }
    
    session = requests.Session()
    
    # Set headers to mimic a real browser
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/json',
        'Origin': 'https://x.com',
        'Referer': 'https://x.com/',
        'X-Twitter-Active-User': 'yes',
        'X-Twitter-Auth-Type': 'OAuth2Session',
        'X-Twitter-Client-Language': 'en',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
    })
    
    try:
        if verbose:
            print("[*] Starting Twitter login via requests (hybrid approach)...")
        
        # Step 1: Get flow token (using minimal browser automation if needed)
        flow_token = None
        if use_browser_for_token:
            flow_token, initial_cookies = extract_flow_token_with_browser(verbose)
            if initial_cookies:
                session.cookies.update(initial_cookies)
        else:
            # Try to get from login page directly (may not work)
            if verbose:
                print("[*] Attempting to get flow token from login page...")
            response = session.get(LOGIN_PAGE)
            # Try to extract from response (unlikely to work without JS execution)
            patterns = [
                r'"flowToken":"([^"]+)"',
                r'flowToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ]
            for pattern in patterns:
                match = re.search(pattern, response.text)
                if match:
                    flow_token = match.group(1)
                    break
        
        if not flow_token:
            result["reason"] = "Could not extract flow token. Twitter requires JavaScript execution to generate flow tokens."
            result["cookies"] = dict(session.cookies)
            return result
        
        # Get CSRF token from cookies
        csrf_token = session.cookies.get('ct0')
        if csrf_token:
            session.headers['X-Csrf-Token'] = csrf_token
        
        if verbose:
            print(f"[*] Flow token obtained: {flow_token[:30]}...")
            print(f"[*] CSRF token: {csrf_token[:20]}..." if csrf_token else "[!] No CSRF token")
        
        # Step 2: Submit username using pure requests
        username_to_use = email_or_username.lstrip('@')
        if verbose:
            print(f"[*] Submitting username: {username_to_use}")
        
        task_url = f"{API_BASE}/onboarding/task.json"
        
        # Submit username
        username_data = {
            "flow_token": flow_token,
            "subtask_inputs": [{
                "subtask_id": "LoginJsInstrumentationSubtask",
                "js_instrumentation": {
                    "response": "{}",
                    "link": "next_link"
                }
            }, {
                "subtask_id": "LoginEnterUserIdentifierSSO",
                "settings_list": {
                    "setting_responses": [{
                        "key": "user_identifier",
                        "response_data": {
                            "text_data": {
                                "result": username_to_use
                            }
                        }
                    }],
                    "link": "next_link"
                }
            }]
        }
        
        response = session.post(task_url, json=username_data)
        
        if verbose:
            print(f"[*] Username submission status: {response.status_code}")
        
        if response.status_code != 200:
            result["reason"] = f"Username submission failed: {response.status_code}"
            result["cookies"] = dict(session.cookies)
            return result
        
        response_data = response.json()
        
        # Update flow token
        if 'flow_token' in response_data:
            flow_token = response_data['flow_token']
        
        # Check if verification is required
        needs_verification = False
        if 'subtasks' in response_data:
            for subtask in response_data.get('subtasks', []):
                subtask_str = json.dumps(subtask).lower()
                if 'enter_text' in subtask_str or 'verification' in subtask_str or 'alternate' in subtask_str:
                    needs_verification = True
                    break
        
        # Step 3: Handle verification if needed (using pure requests)
        if needs_verification:
            if verbose:
                print("[!] Verification required")
            
            if verification_email:
                if verbose:
                    print(f"[*] Submitting verification email: {verification_email}")
                
                verification_data = {
                    "flow_token": flow_token,
                    "subtask_inputs": [{
                        "subtask_id": "LoginEnterAlternateIdentifierSubtask",
                        "enter_text": {
                            "text": verification_email,
                            "link": "next_link"
                        }
                    }]
                }
                
                response = session.post(task_url, json=verification_data)
                
                if verbose:
                    print(f"[*] Verification submission status: {response.status_code}")
                
                if response.status_code == 200:
                    response_data = response.json()
                    if 'flow_token' in response_data:
                        flow_token = response_data['flow_token']
                else:
                    result["reason"] = f"Verification submission failed: {response.status_code}"
                    result["cookies"] = dict(session.cookies)
                    return result
            else:
                result["reason"] = "Verification required but no verification email provided"
                result["cookies"] = dict(session.cookies)
                return result
        
        # Step 4: Submit password using pure requests
        if verbose:
            print("[*] Submitting password...")
        
        password_data = {
            "flow_token": flow_token,
            "subtask_inputs": [{
                "subtask_id": "LoginEnterPassword",
                "enter_password": {
                    "password": password,
                    "link": "next_link"
                }
            }]
        }
        
        response = session.post(task_url, json=password_data)
        
        if verbose:
            print(f"[*] Password submission status: {response.status_code}")
        
        if response.status_code == 200:
            response_data = response.json()
            
            # Check for success indicators
            if 'flow_token' in response_data:
                # Final flow token - check if we're logged in
                final_flow_token = response_data['flow_token']
                
                # Check for auth cookies
                auth_cookies = ['auth_token', 'ct0', 'twid', 'kdt']
                found_cookies = [name for name in auth_cookies if name in session.cookies]
                
                if found_cookies:
                    result["ok"] = True
                    result["reason"] = f"Auth cookies detected: {', '.join(found_cookies)}"
                    result["cookies"] = dict(session.cookies)
                    result["url"] = MAIN_PAGE
                    return result
        
        # Final check - verify login by accessing home page
        if verbose:
            print("[*] Verifying login status...")
        
        home_response = session.get("https://x.com/home")
        
        # Check for auth cookies
        auth_cookies = ['auth_token', 'ct0', 'twid', 'kdt']
        found_cookies = [name for name in auth_cookies if name in session.cookies]
        
        if found_cookies:
            result["ok"] = True
            result["reason"] = f"Auth cookies detected: {', '.join(found_cookies)}"
        else:
            result["reason"] = "Login may have failed - no auth cookies found"
        
        result["url"] = home_response.url
        result["cookies"] = dict(session.cookies)
        
        if verbose:
            print(f"[*] Final status: {result['ok']}")
            print(f"[*] Cookies captured: {len(result['cookies'])} cookies")
    
    except Exception as e:
        result["reason"] = f"Error during login: {str(e)}"
        if verbose:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
        try:
            result["cookies"] = dict(session.cookies)
        except:
            result["cookies"] = {}
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Twitter/X login using requests library (hybrid approach - minimal browser for token extraction)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Note: This script uses minimal browser automation (Selenium) ONLY to extract the initial flow token
from Twitter's JavaScript-rendered login page. All subsequent API calls use pure requests library.

This hybrid approach is necessary because Twitter generates flow tokens dynamically via JavaScript,
which cannot be extracted using pure HTTP requests alone.
        """
    )
    parser.add_argument("--email", required=True, help="Twitter email/username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--verification-email", help="Email address for verification when Twitter requires it (optional)")
    parser.add_argument("--no-browser", action="store_true", help="Disable browser automation (will likely fail)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    result = try_login_requests(
        args.email, 
        args.password, 
        verbose=args.verbose,
        verification_email=args.verification_email,
        use_browser_for_token=not args.no_browser
    )
    
    if args.verbose:
        print("\nResult:")
        pprint.pprint(result)

    if result.get("ok"):
        print("\n[+] Login successful!")
        print(f"  Reason: {result.get('reason')}")
        print(f"  URL: {result.get('url', 'N/A')}")
        print("  Cookies captured:")
        cookies = result.get("cookies", {})
        if cookies:
            for k, v in cookies.items():
                if v:
                    print(f"    - {k}: {v[:50]}..." if len(str(v)) > 50 else f"    - {k}: {v}")
        else:
            print("    (no cookies captured)")
    else:
        print("\n[-] Login not successful:")
        print(f"  Reason: {result.get('reason')}")
        print(f"  URL: {result.get('url', 'N/A')}")
        print("  Cookies captured (if any):")
        cookies = result.get("cookies", {})
        if cookies:
            for k, v in cookies.items():
                if v:
                    print(f"    - {k}: {v[:50]}..." if len(str(v)) > 50 else f"    - {k}: {v}")
        else:
            print("    (no cookies captured)")


if __name__ == "__main__":
    main()

