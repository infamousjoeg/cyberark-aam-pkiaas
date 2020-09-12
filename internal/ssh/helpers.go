package ssh

import (
	"errors"
	"net"
	"regexp"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// ValidateRequestPrincipals Loops through all the Principal values sent in HTTP request to ensure they meet the criteria of either being a hostname or username
func ValidateRequestPrincipals(principals []string) error {
	userRegex := regexp.MustCompile("^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\\$)$")
	hostRegex := regexp.MustCompile("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$")
	for _, principal := range principals {
		if !userRegex.MatchString(principal) && !hostRegex.MatchString(principal) {
			return errors.New("The requested principal: " + principal + " is not a valid principal name")
		}
	}
	return nil
}

// ValidateAllowedPrincipals Validates that all Principals sent in a CreateSSHCertificate request are permitted by
// the template that they are being created against
func ValidateAllowedPrincipals(allowedPrincipals []string, requestPrincipals []string) error {
	if len(allowedPrincipals) == 0 {
		return nil
	}

	err := ValidateRequestPrincipals(requestPrincipals)
	if err != nil {
		return err
	}

	for _, requested := range requestPrincipals {
		permitted := false
		for _, allowed := range allowedPrincipals {
			if requested == allowed {
				permitted = true
			}
		}
		if permitted == false {
			return errors.New("The requested principal: " + requested + " is not in the template's allowed principals list")
		}

	}
	return nil
}

// ValidateRequestHosts Loops through all the hostname values sent in HTTP request to ensure they meet the criteria of either being a hostname or username
func ValidateRequestHosts(hosts []string) error {
	for _, host := range hosts {
		_, _, err := net.ParseCIDR(host)
		if err != nil {
			return errors.New("The requested host: " + host + " needs to be in CIDR format")
		}
	}
	return nil
}

// ValidateAllowedHosts Validates that all hostnames sent in a CreateSSHCertificate request are permitted by
// the template that they are being created against
func ValidateAllowedHosts(allowedHosts []string, requestHosts []string) error {
	if len(allowedHosts) == 0 {
		return nil
	}

	err := ValidateRequestHosts(requestHosts)
	if err != nil {
		return err
	}

	for _, requested := range requestHosts {
		permitted := false
		for _, allowed := range allowedHosts {
			if requested == allowed {
				permitted = true
			}
		}
		if permitted == false {
			return errors.New("The requested host: " + requested + " is not in the template's allowed hosts list")
		}
	}

	return nil
}

// ValidateAllowedCriticalOptions Validates that all critical options sent in a CreateSSHCertificate request
// are permitted by the template that they are being created against
func ValidateAllowedCriticalOptions(allowedCOs []types.SSHCriticalOptions, requestCOs []types.SSHCriticalOptions) error {
	if len(allowedCOs) == 0 {
		return nil
	}

	for _, requested := range requestCOs {
		permitted := false
		for _, allowed := range allowedCOs {
			if requested == allowed {
				permitted = true
			}
		}
		if permitted == false {
			return errors.New("The requested critical option: { \"" + requested.Option + "\":\"" + requested.Value + "\"} is not in the template's allowed critical options list")
		}
	}

	return nil
}

// ValidateAllowedExtensions Validates that all extensions sent in a CreateSSHCertificate request
// are permitted by the template that they are being created against
func ValidateAllowedExtensions(allowedExts []string, requestExts []string) error {
	if len(allowedExts) == 0 {
		return nil
	}

	for _, requested := range requestExts {
		permitted := false
		for _, allowed := range allowedExts {
			if requested == allowed {
				permitted = true
			}
		}
		if permitted == false {
			return errors.New("The requested extension: " + requested + " is not in the template's allowed extensions list")
		}
	}

	return nil
}
