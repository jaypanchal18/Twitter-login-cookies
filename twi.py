import argparse
import time
import pprint
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException


MAIN_PAGE = "https://x.com/"


def is_browser_open(driver):
    """Check if browser is still open and accessible."""
    try:
        _ = driver.current_url
        return True
    except:
        return False


def try_login(email_or_username, password, verbose=False, headless=False, phone_number=None, verification_email=None):
    """
    Login to Twitter/X and return cookies.
    
    Args:
        email_or_username: Email or username
        password: Password
        verbose: Print debug information
        headless: Run browser in headless mode
        phone_number: Optional phone number to try if username fails
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
    
    driver = None
    
    try:
        if verbose:
            print("[*] Launching undetected Chrome browser...")
        
        # Setup undetected Chrome - minimal options
        # undetected-chromedriver handles anti-detection automatically
        options = uc.ChromeOptions()
        if headless:
            options.add_argument('--headless=new')
        else:
            # Keep browser open and stable
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_argument('--start-maximized')
        
        # Create undetected Chrome driver with better error handling
        try:
            if verbose:
                print("[*] Creating Chrome driver...")
            
            # Try creating driver - if it fails, try without version_main
            try:
                driver = uc.Chrome(options=options, version_main=None)
            except Exception as e1:
                if verbose:
                    print(f"[!] First attempt failed: {e1}")
                    print("[*] Trying alternative initialization...")
                # Try without version_main specification
                try:
                    driver = uc.Chrome(options=options)
                except Exception as e2:
                    if verbose:
                        print(f"[!] Alternative initialization also failed: {e2}")
                    result["reason"] = f"Failed to initialize Chrome: {str(e2)}"
                    return result
            
            # Wait a moment for browser to stabilize
            time.sleep(3)
            
            # Verify browser is still open
            try:
                _ = driver.current_url
                if verbose:
                    print("[*] Browser window is open and accessible")
            except Exception as e:
                if verbose:
                    print(f"[!] Browser window closed immediately: {e}")
                result["reason"] = "Browser window closed immediately after launch"
                try:
                    driver.quit()
                except:
                    pass
                return result
            
            if verbose:
                print("[*] Browser launched successfully")
                print(f"[*] Navigating to: {MAIN_PAGE}")
            
            # Navigate to Twitter
            driver.get(MAIN_PAGE)
            
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
                result["reason"] = "Browser disconnected during navigation"
                return result
                
        except Exception as e:
            if verbose:
                print(f"[!] Error launching browser: {e}")
            result["reason"] = f"Failed to launch browser: {str(e)}"
            return result
        
        # Verify browser is still open before proceeding
        if not is_browser_open(driver):
            result["reason"] = "Browser window closed before finding Sign in button"
            result["url"] = "unknown"
            result["cookies"] = {}
            return result
        
        # Find and click Sign in button
        if verbose:
            print("[*] Looking for 'Sign in' button...")
        
        sign_in_selectors = [
            (By.CSS_SELECTOR, 'a[data-testid="loginButton"]'),  # Most reliable - uses data-testid
            (By.CSS_SELECTOR, 'a[href="/login"]'),  # Direct href match
            (By.XPATH, "//a[@href='/login']"),  # XPath version
            (By.XPATH, "//a[contains(@href, 'login')]"),  # Partial href match
            (By.XPATH, "//a[.//span[contains(text(), 'Sign in')]]"),  # Nested span text
            (By.XPATH, "//a[contains(text(), 'Sign in')]"),  # Direct text (may not work due to nesting)
        ]
        
        sign_in_button = None
        for by, selector in sign_in_selectors:
            try:
                sign_in_button = WebDriverWait(driver, 5).until(
                    EC.element_to_be_clickable((by, selector))
                )
                if sign_in_button:
                    if verbose:
                        print(f"[*] Found Sign in button using: {by} - {selector}")
                    break
            except:
                continue
        
        if not sign_in_button:
            # Try waiting a bit longer and scrolling
            if verbose:
                print("[!] Sign in button not found, waiting longer and scrolling...")
            time.sleep(2)
            driver.execute_script("window.scrollTo(0, 0);")
            time.sleep(1)
            
            # Try again with longer wait
            for by, selector in sign_in_selectors[:3]:  # Try top 3 selectors
                try:
                    sign_in_button = WebDriverWait(driver, 10).until(
                        EC.element_to_be_clickable((by, selector))
                    )
                    if sign_in_button:
                        if verbose:
                            print(f"[*] Found Sign in button after retry: {by} - {selector}")
                        break
                except:
                    continue
            
            if not sign_in_button:
                # Debug: show what links are on the page
                if verbose:
                    try:
                        all_links = driver.find_elements(By.TAG_NAME, "a")
                        print(f"[DEBUG] Found {len(all_links)} links on page")
                        for link in all_links[:10]:  # Show first 10
                            try:
                                href = link.get_attribute("href")
                                text = link.text
                                testid = link.get_attribute("data-testid")
                                if "login" in (href or "").lower() or "sign" in (text or "").lower():
                                    print(f"  - Link: href={href}, text='{text}', testid={testid}")
                            except:
                                pass
                    except:
                        pass
                
                result["reason"] = "Could not find 'Sign in' button"
                result["url"] = driver.current_url
                result["cookies"] = {cookie["name"]: cookie["value"] for cookie in driver.get_cookies()}
                return result
        
        # Click Sign in
        if verbose:
            print("[*] Clicking Sign in button...")
        sign_in_button.click()
        time.sleep(3)
        
        # Wait for login form
        if verbose:
            print("[*] Waiting for login form...")
        
        # Find username input
        username_selectors = [
            (By.CSS_SELECTOR, 'input[autocomplete="username"]'),
            (By.CSS_SELECTOR, 'input[name="text"]'),
            (By.CSS_SELECTOR, 'input[type="text"]'),
        ]
        
        username_input = None
        for by, selector in username_selectors:
            try:
                username_input = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((by, selector))
                )
                if username_input:
                    if verbose:
                        print(f"[*] Found username input")
                    break
            except:
                continue
        
        if not username_input:
            result["reason"] = "Could not find username input field"
            result["url"] = driver.current_url
            result["cookies"] = {cookie["name"]: cookie["value"] for cookie in driver.get_cookies()}
            return result
        
        # Enter username (remove @ if present)
        username_to_use = email_or_username.lstrip('@')

        if verbose:
            print(f"[*] Entering username/email: {username_to_use}")
        
        username_input.clear()
        username_input.send_keys(username_to_use)
        time.sleep(1.5)
                
        # Find and click Next button
        if verbose:
            print("[*] Looking for Next button...")
        
        next_button_selectors = [
            (By.XPATH, "//button[contains(text(), 'Next')]"),
            (By.CSS_SELECTOR, 'button[type="submit"]'),
        ]
        
        next_button = None
        for by, selector in next_button_selectors:
            try:
                next_button = WebDriverWait(driver, 5).until(
                    EC.element_to_be_clickable((by, selector))
                )
                if next_button:
                    if verbose:
                        print("[*] Found Next button")
                    break
            except:
                continue
        
        if next_button:
            if verbose:
                print("[*] Clicking Next button...")
            next_button.click()
            time.sleep(3)
        else:
            # Try pressing Enter
            if verbose:
                print("[*] Pressing Enter...")
            username_input.send_keys("\n")
            time.sleep(3)
                
        # Check for error messages after username submission (but don't exit yet - wait for password field)
        verification_detected = False
        try:
            page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            
            # Fatal errors that should cause immediate exit
            fatal_error_keywords = [
                "can't login",
                "can't log in",
                "something went wrong",
                "suspended",
                "locked"
            ]
            
            # Non-fatal warnings that we'll note but continue anyway
            warning_keywords = [
                "try again",
                "unusual activity"
            ]
            
            found_fatal_error = None
            for keyword in fatal_error_keywords:
                if keyword in page_text:
                    found_fatal_error = keyword
                    break
            
            # Check for warnings (non-fatal)
            found_warning = None
            for keyword in warning_keywords:
                if keyword in page_text:
                    found_warning = keyword
                    if verbose:
                        print(f"[!] Warning detected: '{keyword}' - but continuing to check for password field...")
                    break
            
            # Check for verification separately - don't exit immediately
            if "verify" in page_text or "verification" in page_text:
                verification_detected = True
                if verbose:
                    print("[!] Verification may be required, but continuing to check for password field...")
            
            # Only exit immediately for truly fatal errors (not warnings or verification)
            if found_fatal_error:
                if verbose:
                    print(f"[!] Fatal error detected after username entry: '{found_fatal_error}'")
                result["reason"] = f"Twitter error after username: '{found_fatal_error}' - account may require verification or be locked"
                result["url"] = driver.current_url
                result["cookies"] = {cookie["name"]: cookie["value"] for cookie in driver.get_cookies()}
                return result
        except:
            pass
        
        # Wait a bit more for page to update
        time.sleep(3)
        
        # Check if Twitter is asking for phone/email verification after username
        verification_handled = False
        try:
            page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            # Check for the specific verification prompt
            if "enter your phone number" in page_text or "enter your email" in page_text or "unusual login activity" in page_text:
                if verbose:
                    print("[!] Twitter is asking for phone/email verification due to unusual activity")
                
                # Wait a bit more for the page to fully load the verification form
                time.sleep(2)
                
                # Look for the verification input field with more selectors and longer wait
                verification_input = None
                verification_selectors = [
                    (By.CSS_SELECTOR, 'input[data-testid="ocfEnterTextTextInput"]'),
                    (By.CSS_SELECTOR, 'input[autocomplete="tel"]'),
                    (By.CSS_SELECTOR, 'input[autocomplete="email"]'),
                    (By.CSS_SELECTOR, 'input[type="tel"]'),
                    (By.CSS_SELECTOR, 'input[type="email"]'),
                    (By.CSS_SELECTOR, 'input[name="text"]'),
                    (By.CSS_SELECTOR, 'input[placeholder*="phone"]'),
                    (By.CSS_SELECTOR, 'input[placeholder*="email"]'),
                ]
                
                for by, selector in verification_selectors:
                    try:
                        verification_input = WebDriverWait(driver, 8).until(
                            EC.presence_of_element_located((by, selector))
                        )
                        if verification_input and verification_input.is_displayed():
                            if verbose:
                                print(f"[*] Found verification input field using: {by} - {selector}")
                            break
                    except:
                        continue
                
                if verification_input:
                    verification_handled = True
                    # Use email directly for verification
                    if verification_email:
                        if verbose:
                            print(f"[*] Entering email for verification: {verification_email}")
                        try:
                            verification_input.clear()
                            time.sleep(0.5)
                            verification_input.send_keys(verification_email)
                            time.sleep(2)
                            
                            # Click Next button - try multiple methods
                            next_clicked = False
                            next_button_selectors = [
                                (By.CSS_SELECTOR, 'button[data-testid="ocfEnterTextNextButton"]'),
                                (By.XPATH, "//button[contains(text(), 'Next')]"),
                                (By.XPATH, "//div[@role='button' and contains(text(), 'Next')]"),
                                (By.CSS_SELECTOR, 'button[type="button"]'),
                            ]
                            
                            for by, selector in next_button_selectors:
                                try:
                                    next_button = WebDriverWait(driver, 5).until(
                                        EC.element_to_be_clickable((by, selector))
                                    )
                                    if next_button and next_button.is_displayed():
                                        if verbose:
                                            print(f"[*] Found Next button using: {by} - {selector}")
                                        
                                        # Try JavaScript click first (more reliable)
                                        try:
                                            driver.execute_script("arguments[0].click();", next_button)
                                            if verbose:
                                                print("[*] Clicked Next using JavaScript")
                                            next_clicked = True
                                            break
                                        except:
                                            # Fallback to regular click
                                            try:
                                                next_button.click()
                                                if verbose:
                                                    print("[*] Clicked Next using regular click")
                                                next_clicked = True
                                                break
                                            except Exception as e:
                                                if verbose:
                                                    print(f"[!] Error clicking: {e}")
                                                continue
                                except:
                                    continue
                            
                            if not next_clicked:
                                if verbose:
                                    print("[!] Could not find/click Next button, trying Enter key...")
                                verification_input.send_keys("\n")
                            
                            # Wait for page to process
                            time.sleep(5)
                            
                            # Check if "try again" or "incorrect" message appeared
                            try:
                                page_text_after = driver.find_element(By.TAG_NAME, "body").text.lower()
                                if "try again" in page_text_after or "incorrect" in page_text_after:
                                    if verbose:
                                        print("[!] 'Try again' or 'Incorrect' message detected. Waiting longer...")
                                    time.sleep(5)
                                    
                                    # Check if password field appeared despite error message
                                    try:
                                        temp_password = driver.find_element(By.CSS_SELECTOR, 'input[type="password"]')
                                        if temp_password and temp_password.is_displayed():
                                            if verbose:
                                                print("[*] Password field appeared! Continuing with login...")
                                    except:
                                        # Try clicking Next one more time
                                        try:
                                            next_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Next')]")
                                            if next_button and next_button.is_displayed() and next_button.is_enabled():
                                                driver.execute_script("arguments[0].click();", next_button)
                                                if verbose:
                                                    print("[*] Retried clicking Next button")
                                                time.sleep(5)
                                        except:
                                            pass
                            except:
                                pass
                            
                            # Additional wait for Twitter to process
                            time.sleep(3)
                        except Exception as e:
                            if verbose:
                                print(f"[!] Error entering email: {e}")
                    else:
                        # No verification email provided - wait for manual entry
                        if verbose:
                            print("[!] No verification email provided. Please enter email manually in browser...")
                            print("[*] Waiting 30 seconds for manual verification entry...")
                        time.sleep(30)
                        
                        # After waiting, try to find Next button and click it (in case user entered manually)
                        try:
                            next_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Next')]")
                            if next_button and next_button.is_enabled():
                                next_button.click()
                                if verbose:
                                    print("[*] Clicked Next after manual entry")
                                time.sleep(4)
                        except:
                            pass
                else:
                    if verbose:
                        print("[!] Could not find verification input field, but verification prompt detected")
        except Exception as e:
            if verbose:
                print(f"[!] Error checking for verification prompt: {e}")
        
        # Check if password field appeared
        password_input = None
        password_selectors = [
            (By.CSS_SELECTOR, 'input[type="password"]'),
            (By.CSS_SELECTOR, 'input[name="password"]'),
        ]
        
        for by, selector in password_selectors:
            try:
                password_input = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((by, selector))
                )
                if password_input:
                    if verbose:
                        print("[*] Password field found!")
                    break
            except:
                continue
        
        if not password_input:
            # Check current URL and page content
            current_url = driver.current_url
            try:
                page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            except:
                page_text = ""
            
            # Check if we're on a verification/challenge page
            if "challenge" in current_url.lower() or "verify" in current_url.lower():
                result["reason"] = "Account requires verification/challenge - please complete manually in browser"
                if verbose:
                    print("[!] Verification challenge detected. Browser will stay open for manual completion.")
                    print("[!] After completing verification, the script will continue...")
            elif "verify" in page_text or "verification" in page_text:
                result["reason"] = "Account requires phone/email verification"
            elif "suspended" in page_text:
                result["reason"] = "Account may be suspended"
            else:
                result["reason"] = "Could not find password field - account may require verification"
            
            result["url"] = current_url
            result["cookies"] = {cookie["name"]: cookie["value"] for cookie in driver.get_cookies()}
            
            # If verification is required, wait a bit longer to see if user completes it manually
            if verification_detected or "challenge" in current_url.lower() or "verify" in current_url.lower():
                if verbose:
                    print("[*] Waiting 15 seconds for manual verification completion...")
                time.sleep(15)
                
                # Check again for password field after waiting
                for by, selector in password_selectors:
                    try:
                        password_input = WebDriverWait(driver, 5).until(
                            EC.presence_of_element_located((by, selector))
                        )
                        if password_input:
                            if verbose:
                                print("[*] Password field found after verification!")
                            break
                    except:
                        continue
                
                # If still no password field, return the error
                if not password_input:
                    return result
            
            if not password_input:
                return result
        
        # Enter password
        if verbose:
            print("[*] Entering password...")
        
        password_input.clear()
        password_input.send_keys(password)
        time.sleep(1)
        
        # Find and click Log in button
        if verbose:
            print("[*] Looking for Log in button...")
        
        login_button_selectors = [
            (By.XPATH, "//button[contains(text(), 'Log in')]"),
            (By.XPATH, "//button[contains(text(), 'Login')]"),
            (By.CSS_SELECTOR, 'button[type="submit"]'),
        ]
        
        login_button = None
        for by, selector in login_button_selectors:
            try:
                login_button = driver.find_element(by, selector)
                if login_button and login_button.is_displayed():
                    if verbose:
                        print("[*] Found Log in button")
                    break
            except:
                continue
        
        if login_button:
            if verbose:
                print("[*] Clicking Log in button...")
            login_button.click()
        else:
            # Try pressing Enter
            if verbose:
                print("[*] Pressing Enter...")
            password_input.send_keys("\n")
        
        # Wait for login to complete
        if verbose:
            print("[*] Waiting for login to complete...")
        
        # Wait and check multiple times for navigation or auth cookies
        login_successful = False
        current_url = None
        
        for i in range(6):  # Check 6 times over 15 seconds
            time.sleep(2.5)
            try:
                # Re-get current URL each time (avoid stale references)
                current_url = driver.current_url
                
                if verbose and i % 2 == 0:
                    print(f"[*] Checking login status... (attempt {i+1}/6, URL: {current_url})")
                
                # Check if we're on home page
                if "home" in current_url.lower() or "/i/home" in current_url or current_url == "https://x.com/home":
                    result["ok"] = True
                    result["reason"] = "Successfully logged in - redirected to home"
                    result["url"] = current_url
                    login_successful = True
                    break
                
                # Check for challenge/verification
                if "challenge" in current_url.lower() or "login_verification" in current_url.lower():
                    result["reason"] = "Login challenge required (2FA/CAPTCHA)"
                    result["url"] = current_url
                    break
                
                # Check for auth cookies (re-get cookies each time)
                try:
                    cookies = driver.get_cookies()
                    cookie_dict = {c["name"]: c["value"] for c in cookies}
                    auth_cookie_names = ["auth_token", "ct0", "twid", "kdt", "remember_checked_on"]
                    found_auth_cookies = [name for name in auth_cookie_names if name in cookie_dict]
                    
                    if found_auth_cookies:
                        if verbose:
                            print(f"[*] Found auth cookies: {found_auth_cookies}")
                        result["ok"] = True
                        result["reason"] = f"Auth cookies detected ({', '.join(found_auth_cookies)}) - logged in"
                        result["url"] = current_url
                        login_successful = True
                        break
                except Exception as cookie_error:
                    if verbose:
                        print(f"[!] Error getting cookies: {cookie_error}")
                
                # Check for error messages on page (re-find element each time)
                try:
                    body_element = driver.find_element(By.TAG_NAME, "body")
                    page_text = body_element.text.lower()
                    if "incorrect" in page_text or "wrong password" in page_text:
                        result["reason"] = "Incorrect password"
                        result["url"] = current_url
                        break
                    elif "verify" in page_text or "verification" in page_text:
                        result["reason"] = "Account requires verification"
                        result["url"] = current_url
                        break
                    elif "can't login" in page_text or "can't log in" in page_text or "try again" in page_text:
                        result["reason"] = "Twitter error: Can't login - try again. Account may require verification."
                        result["url"] = current_url
                        break
                except Exception as page_error:
                    # Element might be stale, continue
                    if verbose and i == 0:
                        print(f"[!] Could not read page text: {page_error}")
                    pass
                
            except Exception as e:
                if verbose:
                    print(f"[!] Error checking login status: {e}")
                # Continue to next iteration
                continue
        
        # Final check if still not determined
        if not login_successful and not result.get("reason"):
            try:
                current_url = driver.current_url
                cookies = driver.get_cookies()
                cookie_dict = {c["name"]: c["value"] for c in cookies}
                
                # Check one more time for auth cookies
                auth_cookie_names = ["auth_token", "ct0", "twid"]
                found_auth_cookies = [name for name in auth_cookie_names if name in cookie_dict]
                
                if found_auth_cookies:
                    result["ok"] = True
                    result["reason"] = f"Auth cookies found after wait: {', '.join(found_auth_cookies)}"
                elif "/i/flow/login" in current_url:
                    result["reason"] = "Still on login page - login may have failed or requires verification"
                else:
                    result["reason"] = f"Unknown state - URL: {current_url}"
                
                result["url"] = current_url
            except:
                result["reason"] = "Could not determine login status"
                result["url"] = "unknown"
        
        # Get all cookies
        result["cookies"] = {cookie["name"]: cookie["value"] for cookie in driver.get_cookies()}
        
        if verbose:
            print(f"[*] Final URL: {result['url']}")
            print(f"[*] Cookies captured: {len(result['cookies'])} cookies")
    
    except Exception as e:
        result["reason"] = f"Error during login: {str(e)}"
        if verbose:
            print(f"[!] Error: {e}")
        try:
            result["url"] = driver.current_url if driver else "unknown"
            result["cookies"] = {cookie["name"]: cookie["value"] for cookie in driver.get_cookies()} if driver else {}
        except:
            result["cookies"] = {}
    
    finally:
        if driver:
            if verbose:
                print("[*] Closing browser...")
            driver.quit()
    
    return result


def main():
    parser = argparse.ArgumentParser(description="Twitter/X login using undetected-chromedriver")
    parser.add_argument("--email", required=True, help="Twitter email/username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--phone", help="Phone number to try if username doesn't work (optional)")
    parser.add_argument("--verification-email", help="Email address for verification when Twitter requires it (optional)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    args = parser.parse_args()

    result = try_login(
        args.email, 
        args.password, 
        verbose=args.verbose, 
        headless=args.headless,
        phone_number=args.phone,
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
            if isinstance(cookies, list):
                cookies = {cookie.get("name", ""): cookie.get("value", "") for cookie in cookies}
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
            if isinstance(cookies, list):
                cookies = {cookie.get("name", ""): cookie.get("value", "") for cookie in cookies}
            for k, v in cookies.items():
                if v:
                    print(f"    - {k}: {v[:50]}..." if len(str(v)) > 50 else f"    - {k}: {v}")
        else:
            print("    (no cookies captured)")


if __name__ == "__main__":
    main()
