package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/playwright-community/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var logger = logrus.WithField("provider", "browser")

const DEFAULT_TIMEOUT float64 = 300000

// Client client for browser based Identity Provider
type Client struct {
	BrowserType           string
	BrowserExecutablePath string
	Headless              bool
	// Setup alternative directory to download playwright browsers to
	BrowserDriverDir    string
	Timeout             int
	BrowserAutoFill     bool
	BrowserOktaAutoFill bool
}

// New create new browser based client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{
		Headless:              idpAccount.Headless,
		BrowserDriverDir:      idpAccount.BrowserDriverDir,
		BrowserType:           strings.ToLower(idpAccount.BrowserType),
		BrowserExecutablePath: idpAccount.BrowserExecutablePath,
		Timeout:               idpAccount.Timeout,
		BrowserAutoFill:       idpAccount.BrowserAutoFill,
		BrowserOktaAutoFill:   idpAccount.BrowserOktaAutoFill,
	}, nil
}

// contains checks if a string is present in a slice
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
func (cl *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	runOptions := playwright.RunOptions{}
	if cl.BrowserDriverDir != "" {
		runOptions.DriverDirectory = cl.BrowserDriverDir
	}

	// Optionally download browser drivers if specified
	if loginDetails.DownloadBrowser {
		err := playwright.Install(&runOptions)
		if err != nil {
			return "", err
		}
	}

	playwrightInstallAttemptOnRunError := false
playwrightRun:
	pw, err := playwright.Run(&runOptions)
	if err != nil {
		if playwrightInstallAttemptOnRunError { // to avoid a loop
			return "", err
		}
		if strings.Contains(err.Error(), "could not start driver") && !loginDetails.DownloadBrowser {
			playwrightInstallAttemptOnRunError = true
			logger.Warnf("playwright run failed due to error '%v', attempting to download browser drivers...", err)
			err = playwright.Install(&runOptions)
			if err != nil {
				return "", err
			}
			goto playwrightRun
		}
		return "", err
	}

	// TODO: provide some overrides for this window
	launchOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(cl.Headless),
	}

	validBrowserTypes := []string{"chromium", "firefox", "webkit", "chrome", "chrome-beta", "chrome-dev", "chrome-canary", "msedge", "msedge-beta", "msedge-dev", "msedge-canary"}
	if len(cl.BrowserType) > 0 && !contains(validBrowserTypes, cl.BrowserType) {
		return "", fmt.Errorf("invalid browser-type: '%s', only %s are allowed", cl.BrowserType, validBrowserTypes)
	}

	if cl.BrowserType != "" {
		logger.Info(fmt.Sprintf("Setting browser type: %s", cl.BrowserType))
		launchOptions.Channel = playwright.String(cl.BrowserType)
	}

	// Default browser is Chromium as it is widely supported for Identity providers,
	// It can also be set to the other playwright browsers: Firefox and WebKit
	browserType := pw.Chromium
	if cl.BrowserType == "firefox" {
		browserType = pw.Firefox
	} else if cl.BrowserType == "webkit" {
		browserType = pw.WebKit
	}

	// You can set the path to a browser executable to run instead of the playwright-go bundled one. If `executablePath`
	// is a relative path, then it is resolved relative to the current working directory.
	// Note that Playwright only works with the bundled Chromium, Firefox or WebKit, use at your own risk. see:
	if len(cl.BrowserExecutablePath) > 0 {
		logger.Info(fmt.Sprintf("Setting browser executable path: %s", cl.BrowserExecutablePath))
		launchOptions.ExecutablePath = &cl.BrowserExecutablePath
	}

	// currently using the main browsers supported by Playwright: Chromium, Firefox or Webkit
	//
	// this is a sandboxed browser window so password managers and addons are separate
	browser, err := browserType.Launch(launchOptions)
	if err != nil {
		return "", err
	}

	page, err := browser.NewPage()
	if err != nil {
		return "", err
	}

	defer func() {
		logger.Info("clean up browser")
		if err := browser.Close(); err != nil {
			logger.Info("Error when closing browser", err)
		}
		if err := pw.Stop(); err != nil {
			logger.Info("Error when stopping pm", err)
		}
	}()

	return getSAMLResponse(page, loginDetails, cl)
}

var getSAMLResponse = func(page playwright.Page, loginDetails *creds.LoginDetails, client *Client) (string, error) {
	if client.BrowserOktaAutoFill {
		return getOktaSAMLResponse(page, loginDetails, client)
	}

	logger.WithField("URL", loginDetails.URL).Info("opening browser")

	if _, err := page.Goto(loginDetails.URL); err != nil {
		return "", err
	}

	if client.BrowserAutoFill {
		err := autoFill(page, loginDetails)
		if err != nil {
			logger.Error("error when auto filling", err)
		}
	}

	// https://docs.aws.amazon.com/general/latest/gr/signin-service.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Ningxia.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
	signin_re, err := signinRegex()
	if err != nil {
		return "", err
	}

	logger.Info("waiting ...")
	r, _ := page.ExpectRequest(signin_re, nil, client.expectRequestTimeout())
	data, err := r.PostData()
	if err != nil {
		return "", err
	}

	values, err := url.ParseQuery(data)
	if err != nil {
		return "", err
	}

	return values.Get("SAMLResponse"), nil
}

func pageWaitForOneOfLocatorVisible(page playwright.Page, selectors []string) (playwright.Locator, *string, error) {
	var locator playwright.Locator
	var locatorErrors []error
	var matchedSelectorStr string // for debug output
	for _, k := range selectors {
		selectorStr := k
		locator = page.Locator(selectorStr)
		err := locator.WaitFor(playwright.LocatorWaitForOptions{
			State: playwright.WaitForSelectorStateVisible,
		})
		if err != nil {
			locatorErrors = append(locatorErrors, err)
		} else {
			matchedSelectorStr = selectorStr
			break
		}
	}
	if locator == nil {
		return nil, nil, fmt.Errorf("error finding one or more selectors in the list: %v", locatorErrors)
	} else {
		return locator, &matchedSelectorStr, nil
	}
}

func findPlaywrightCookiesInCredentialStore(loginDetails *creds.LoginDetails) ([]playwright.OptionalCookie, error) {
	credHelperPlaywrightCookiesUrl := loginDetails.URL + "/playwrightCookies"
	var foundCookies []playwright.OptionalCookie
	// check for existing cookies in keychain
	_, playwrightCookies, err := credentials.CurrentHelper.Get(credHelperPlaywrightCookiesUrl)
	if err != nil {
		return nil, fmt.Errorf("no playwright cookies found in keychain for '%s'", loginDetails.URL)
	} else {
		if playwrightCookies == "expiredCookies" {
			return nil, fmt.Errorf("playwright cookies found in keychain for '%s' are expired")
		} else {
			err = json.Unmarshal([]byte(playwrightCookies), &foundCookies)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling playwright cookies found in keychain for '%s': %v", loginDetails.URL, err)
			}
		}
	}
	return foundCookies, nil
}

func setPlaywrightCookiesAsExpiredInCredentialStore(loginDetails *creds.LoginDetails) error {
	credHelperPlaywrightCookiesUrl := loginDetails.URL + "/playwrightCookies"
	err := credentials.SaveCredentials(credHelperPlaywrightCookiesUrl, loginDetails.Username, "expiredCookies")
	if err != nil {
		return fmt.Errorf("error clearing playwright cookies for '%s' in keychain: %v", loginDetails.URL, err)
	}
	return nil
}

func savePlaywrightCookiesInCredentialStore(loginDetails *creds.LoginDetails, cookies []playwright.OptionalCookie) error {
	if cookies == nil {
		return fmt.Errorf("nil cookies")
	}
	credHelperPlaywrightCookiesUrl := loginDetails.URL + "/playwrightCookies"
	allCookiesJsonBytes, err := json.Marshal(cookies)
	if err != nil {
		logger.Debugf("error marshaling playwright active browser cookies for '%s': %v", loginDetails.URL, err)
	} else {
		err = credentials.SaveCredentials(credHelperPlaywrightCookiesUrl, loginDetails.Username, string(allCookiesJsonBytes))
		if err != nil {
			return fmt.Errorf("error saving playwright active browser cookies for '%s' in keychain: %v", loginDetails.URL, err)
		}
	}
	return nil
}

func addPlaywrightCookiesToPage(page playwright.Page, cookies []playwright.OptionalCookie) error {
	if cookies == nil {
		return fmt.Errorf("nil cookies")
	}
	for _, fc := range cookies {
		foundCookie := fc
		if foundCookie.URL != nil && foundCookie.Domain != nil {
			foundCookie.URL = nil
		}
		if foundCookie.Expires != nil && foundCookie.Name == "aws-vid" { // aws-vid cookie expiry breaks playwright for some reason
			expInt := time.Now().Add(time.Hour * 24 * 300).Unix()
			expF := float64(expInt)
			tmpFc := foundCookie
			tmpFc.Expires = &expF
			foundCookie = tmpFc
		}
		err := page.Context().AddCookies([]playwright.OptionalCookie{foundCookie})
		if err != nil {
			return fmt.Errorf("error adding playwright cookie name='%s',domain='%s': %v", foundCookie.Name, *foundCookie.Domain, err)
		}
	}
	return nil
}

var getOktaSAMLResponse = func(page playwright.Page, loginDetails *creds.LoginDetails, client *Client) (string, error) {
	logger.WithField("URL", loginDetails.URL).Info("opening browser")

	// check for existing cookies in keychain
	foundCookies, cookieErr := findPlaywrightCookiesInCredentialStore(loginDetails)

	if cookieErr == nil {
		cookieErr = addPlaywrightCookiesToPage(page, foundCookies)
	}

	if _, err := page.Goto(loginDetails.URL); err != nil {
		return "", err
	}

	pageIsAwsSamlPage := false
	if cookieErr == nil { // if found cookies were successfully loaded
		// check if the url navigation ends up in aws saml page
		signin_re, err := signinRegex()
		if err == nil {
			logger.Info("checking if stored browser cookies are valid...")
			timeoutMillis := 5000.0
			resp, _ := page.ExpectRequest(signin_re, nil, playwright.PageExpectRequestOptions{Timeout: &timeoutMillis})
			if resp == nil || (resp != nil && !signin_re.MatchString(resp.URL())) {
				logger.Info("stored browser cookies are expired, clearing cookies & resuming standard sign-in process")
				cookieErr = fmt.Errorf("expired cookies")
				err = page.Context().ClearCookies()
				if err != nil {
					logger.Debugf("error clearing active browser cookies: %v", err)
				}
				err = setPlaywrightCookiesAsExpiredInCredentialStore(loginDetails)
				if err != nil {
					logger.Debugf("setPlaywrightCookiesAsExpiredInCredentialStore error: %v", err)
				}
				if _, err := page.Goto(loginDetails.URL); err != nil {
					return "", err
				}
			} else {
				pageIsAwsSamlPage = true
			}
		}
	}

	oktaUsernameInputSelectors := []string{"input[name=\"identifier\"]", "input[autocomplete=\"username\"]"}
	oktaRememberMeCheckboxSelectors := []string{"input[type=\"checkbox\"][name=\"rememberMe\"]"}
	oktaNextButtonSelectors := []string{"input[type=\"submit\"][value=\"Next\"]"}
	oktaPasswordInputSelectors := []string{"input[type=\"password\"]"}
	oktaVerifyButtonSelectors := []string{"input[type=\"submit\"][value=\"Verify\"]"}
	// okta_verify-totp for code - Not implemented
	oktaMFASelectButtonSelectors := []string{"div[class=authenticator-button][data-se=\"okta_verify-push\"]"}

	if cookieErr != nil { // if found cookies has errors loading
		logger.Debugf("starting okta login page automation...")
		usernameInputLocator, matchedUsernameInputSelectorStr, err := pageWaitForOneOfLocatorVisible(page, oktaUsernameInputSelectors)
		if err != nil {
			logger.Debugf("okta username selector not found!, navigating to %s", loginDetails.URL)
			if _, err := page.Goto(loginDetails.URL); err != nil {
				return "", err
			}
		} else {
			logger.Debugf("okta username selector '%s' selector is visible...", *matchedUsernameInputSelectorStr)
		}

		err = usernameInputLocator.Fill(loginDetails.Username)
		if err != nil {
			return "", fmt.Errorf("error filling in okta username field: %v", err)
		}

		rememberMeCheckboxSelector, matchedRememberMeCheckboxSelectorStr, err := pageWaitForOneOfLocatorVisible(page, oktaRememberMeCheckboxSelectors)
		if err != nil {
			logger.Debug("okta remember me checkbox selector not found!")
		} else {
			logger.Debugf("okta remember me checkbox selector '%s' found, attempting to check it...", *matchedRememberMeCheckboxSelectorStr)
			timeout := 1500.0
			forceCheck := true
			err = rememberMeCheckboxSelector.Check(playwright.LocatorCheckOptions{
				Force:   &forceCheck,
				Timeout: &timeout,
			})
			if err != nil {
				logger.Debugf("error checking the okta remember me checkbox: %v", err)
			}
		}

		nextButtonSelector, matchedNextButtonSelectorStr, err := pageWaitForOneOfLocatorVisible(page, oktaNextButtonSelectors)
		if err != nil {
			return "", fmt.Errorf("okta Next button not found: %v", err)
		} else {
			logger.Debugf("okta Next button selector '%s' selector is visible...", *matchedNextButtonSelectorStr)
		}

		err = nextButtonSelector.Click()
		if err != nil {
			return "", fmt.Errorf("error clicking okta Next button: %v", err)
		}

		passwordInputLocator, matchedPasswordInputSelectorStr, err := pageWaitForOneOfLocatorVisible(page, oktaPasswordInputSelectors)
		if err != nil {
			return "", fmt.Errorf("okta password selector not found: %v", err)
		} else {
			logger.Debugf("okta password selector '%s' selector is visible...", *matchedPasswordInputSelectorStr)
		}

		err = passwordInputLocator.Fill(loginDetails.Password)
		if err != nil {
			return "", fmt.Errorf("error filling in okta password field: %v", err)
		}

		verifyButtonSelector, matchedVerifyButtonSelectorStr, err := pageWaitForOneOfLocatorVisible(page, oktaVerifyButtonSelectors)
		if err != nil {
			return "", fmt.Errorf("okta Verify button not found: %v", err)
		} else {
			logger.Debugf("okta Verify button selector '%s' selector is visible...", *matchedVerifyButtonSelectorStr)
		}

		err = verifyButtonSelector.Click()
		if err != nil {
			return "", fmt.Errorf("error clicking okta Verify button: %v", err)
		}

		mfaSelectButtonSelector, matchedMFASelectButtonSelectorStr, err := pageWaitForOneOfLocatorVisible(page, oktaMFASelectButtonSelectors)
		if err != nil {
			return "", fmt.Errorf("okta MFA Select button not found: %v", err)
		} else {
			logger.Debugf("okta MFA Select button selector '%s' selector is visible...", *matchedMFASelectButtonSelectorStr)
		}

		err = mfaSelectButtonSelector.Click()
		if err != nil {
			return "", fmt.Errorf("error clicking okta MFA Select button: %v", err)
		}

		logger.Debugf("ui element query automation complete")
	}

	// https://docs.aws.amazon.com/general/latest/gr/signin-service.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Ningxia.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
	signin_re, err := signinRegex()
	if err != nil {
		return "", err
	}

	fmt.Println("waiting ...")
	if pageIsAwsSamlPage {
		go func() {
			time.Sleep(5 * time.Second)
			page.Reload()
		}()
	}
	r, _ := page.ExpectRequest(signin_re, nil, client.expectRequestTimeout())
	data, err := r.PostData()
	if err != nil {
		return "", err
	}

	values, err := url.ParseQuery(data)
	if err != nil {
		return "", err
	}
	pageCookies, err := page.Context().Cookies()
	if err != nil {
		logger.Debugf("error getting playwright active browser cookies for '%s': %v", loginDetails.URL, err)
	} else {
		var allCookies []playwright.OptionalCookie
		for _, k := range pageCookies {
			tmpCookie := k
			optCookie := tmpCookie.ToOptionalCookie()
			allCookies = append(allCookies, optCookie)
		}
		err = savePlaywrightCookiesInCredentialStore(loginDetails, allCookies)
		if err != nil {
			logger.Debugf("error saving playwright active browser cookies for '%s' in keychain: %v", loginDetails.URL, err)
		}
	}
	return values.Get("SAMLResponse"), nil
}

var autoFill = func(page playwright.Page, loginDetails *creds.LoginDetails) error {
	passwordField := page.Locator("input[type='password']")
	err := passwordField.WaitFor(playwright.LocatorWaitForOptions{
		State: playwright.WaitForSelectorStateVisible,
	})

	if err != nil {
		return err
	}

	err = passwordField.Fill(loginDetails.Password)
	if err != nil {
		return err
	}

	keyboard := page.Keyboard()

	// move to username field which is above password field
	err = keyboard.Press("Shift+Tab")
	if err != nil {
		return err
	}

	err = keyboard.InsertText(loginDetails.Username)
	if err != nil {
		return err
	}

	// Find the submit button or input of the form that the password field is in
	submitLocator := page.Locator("form", playwright.PageLocatorOptions{
		Has: passwordField,
	}).Locator("[type='submit']")
	count, err := submitLocator.Count()
	if err != nil {
		return err
	}

	// when submit locator exists, Click it
	if count > 0 {
		return submitLocator.Click()
	} else { // Use javascript to submit the form when no submit input or button is found
		_, err := page.Evaluate(`document.querySelector('input[type="password"]').form.submit()`, nil)
		return err
	}
}

func signinRegex() (*regexp.Regexp, error) {
	// https://docs.aws.amazon.com/general/latest/gr/signin-service.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Ningxia.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
	return regexp.Compile(`https:\/\/((.*\.)?signin\.(aws\.amazon\.com|amazonaws-us-gov\.com|amazonaws\.cn))\/saml`)
}

func (cl *Client) Validate(loginDetails *creds.LoginDetails) error {

	if loginDetails.URL == "" {
		return errors.New("empty URL")
	}

	return nil
}

func (cl *Client) expectRequestTimeout() playwright.PageExpectRequestOptions {
	timeout := float64(cl.Timeout)
	if timeout < 30000 {
		timeout = DEFAULT_TIMEOUT
	}
	return playwright.PageExpectRequestOptions{Timeout: &timeout}
}
