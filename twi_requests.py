import argparse
import time
import pprint
import requests
import re
import json
from urllib.parse import urlparse, parse_qs


MAIN_PAGE = "https://x.com/"


def get_csrf_token(session):
    """Extract CSRF token from cookies or page."""
    # Try to get from cookies first
    if 'ct0' in session.cookies:
        return session.cookies['ct0']
    
    # Try to get from page
    try:
        response = session.get(MAIN_PAGE)
        # Look for ct0 in cookies
        if 'ct0' in session.cookies:
            return session.cookies['ct0']
        
        # Try to extract from JavaScript in page
        ct0_match = re.search(r'"ct0":"([^"]+)"', response.text)
        if ct0_match:
            return ct0_match.group(1)
    except:
        pass
    
    return None


def try_login_requests(email_or_username, password, verbose=False, verification_email=None):
    """
    Login to Twitter/X using requests library and return cookies.
    
    Args:
        email_or_username: Email or username
        password: Password
        verbose: Print debug information
        verification_email: Optional email address for verification when Twitter requires it
    
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
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
    })
    
    try:
        if verbose:
            print("[*] Starting Twitter login via requests...")
        
        # Step 1: Get initial page to establish session and get cookies
        if verbose:
            print("[*] Getting initial page...")
        
        response = session.get(MAIN_PAGE)
        if verbose:
            print(f"[*] Initial page status: {response.status_code}")
        
        # Get CSRF token
        csrf_token = get_csrf_token(session)
        if not csrf_token:
            # Try to get from cookies after initial request
            for cookie in session.cookies:
                if cookie.name == 'ct0':
                    csrf_token = cookie.value
                    break
        
        if verbose:
            print(f"[*] CSRF token: {csrf_token[:20]}..." if csrf_token else "[!] No CSRF token found")
        
        # Step 2: Initiate login flow
        if verbose:
            print("[*] Initiating login flow...")
        
        # Twitter uses /i/api/1.1/onboarding/task.json endpoint for login
        login_init_url = "https://x.com/i/api/1.1/onboarding/task.json"
        
        # Update headers for API request
        session.headers.update({
            'Content-Type': 'application/json',
            'X-Twitter-Active-User': 'yes',
            'X-Twitter-Auth-Type': 'OAuth2Session',
            'X-Twitter-Client-Language': 'en',
        })
        
        if csrf_token:
            session.headers['X-Csrf-Token'] = csrf_token
        
        # Step 3: Enter username
        if verbose:
            print(f"[*] Entering username: {email_or_username}")
        
        username_to_use = email_or_username.lstrip('@')
        
        # Twitter login flow - first step: enter username
        # This is complex as Twitter uses a multi-step flow with specific endpoints
        # We'll try the direct login endpoint approach
        
        login_url = "https://x.com/i/api/1.1/onboarding/task.json"
        
        # Get the login flow task
        flow_data = {
            "flow_token": None,
            "input_flow_data": {
                "flow_context": {
                    "debug_overrides": {},
                    "start_location": {
                        "location": "unknown"
                    }
                }
            }
        }
        
        # Alternative approach: Use the web login endpoint
        # Twitter's actual login happens through /i/api/1.1/onboarding/task.json
        # But we need to get the flow_token first
        
        # Try accessing login page to get flow token
        login_page_url = "https://x.com/i/flow/login"
        response = session.get(login_page_url)
        
        # Extract flow_token from the page - Twitter embeds it in JavaScript
        flow_token = None
        
        # Try multiple patterns to find flow token
        patterns = [
            r'"flowToken":"([^"]+)"',
            r'flow_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'flowToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'"flow_token":"([^"]+)"',
            r'flowToken=([^&\s"\']+)',
        ]
        
        for pattern in patterns:
            flow_token_match = re.search(pattern, response.text)
            if flow_token_match:
                flow_token = flow_token_match.group(1)
                break
        
        # Also try to extract from window.__INITIAL_STATE__ or similar
        if not flow_token:
            state_match = re.search(r'window\.__INITIAL_STATE__\s*=\s*({.+?});', response.text, re.DOTALL)
            if state_match:
                import json
                try:
                    state_data = json.loads(state_match.group(1))
                    # Navigate through state to find flow_token
                    if 'flow' in state_data and 'flowToken' in state_data['flow']:
                        flow_token = state_data['flow']['flowToken']
                except:
                    pass
        
        if verbose:
            print(f"[*] Flow token: {flow_token[:30]}..." if flow_token else "[!] No flow token found")
        
        if not flow_token:
            if verbose:
                print("[!] Could not extract flow token from page.")
                print("[!] Note: Twitter's login API is complex and may require browser automation.")
                print("[!] Consider using the Selenium version (twi.py) for more reliable login.")
            
            result["reason"] = "Could not extract flow token. Twitter's login requires complex flow token handling. Use Selenium version for better reliability."
            result["url"] = login_page_url
            result["cookies"] = dict(session.cookies)
            return result
        
        # Step 4: Submit username
        if verbose:
            print("[*] Submitting username...")
        
        # Submit username in the flow
        task_data = {
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
        
        session.headers['Content-Type'] = 'application/json'
        if csrf_token:
            session.headers['X-Csrf-Token'] = csrf_token
        
        response = session.post(username_submit_url, json=task_data)
        
        if verbose:
            print(f"[*] Username submission status: {response.status_code}")
            if response.status_code != 200:
                print(f"[!] Response: {response.text[:200]}")
        
        # Check if verification is required
        response_data = response.json() if response.status_code == 200 else {}
        
        if 'flow_token' in response_data:
            flow_token = response_data['flow_token']
        
        # Check for verification requirement
        if 'subtasks' in response_data:
            for subtask in response_data.get('subtasks', []):
                if 'enter_text' in str(subtask).lower() or 'verification' in str(subtask).lower():
                    if verbose:
                        print("[!] Verification required")
                    
                    if verification_email:
                        if verbose:
                            print(f"[*] Submitting verification email: {verification_email}")
                        
                        # Submit verification email
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
                        
                        response = session.post(username_submit_url, json=verification_data)
                        if verbose:
                            print(f"[*] Verification submission status: {response.status_code}")
                        
                        if response.status_code == 200:
                            response_data = response.json()
                            if 'flow_token' in response_data:
                                flow_token = response_data['flow_token']
        
        # Step 5: Submit password
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
        
        response = session.post(username_submit_url, json=password_data)
        
        if verbose:
            print(f"[*] Password submission status: {response.status_code}")
        
        if response.status_code == 200:
            response_data = response.json()
            
            # Check for success
            if 'flow_token' in response_data:
                # Check if we're logged in
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
        
        # Final check - try accessing home page
        if verbose:
            print("[*] Checking login status...")
        
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
        try:
            result["cookies"] = dict(session.cookies)
            result["url"] = session.get(MAIN_PAGE).url if session else "unknown"
        except:
            result["cookies"] = {}
    
    return result


def main():
    parser = argparse.ArgumentParser(description="Twitter/X login using requests library")
    parser.add_argument("--email", required=True, help="Twitter email/username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--verification-email", help="Email address for verification when Twitter requires it (optional)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    result = try_login_requests(
        args.email, 
        args.password, 
        verbose=args.verbose,
        verification_email=args.verification_email
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

