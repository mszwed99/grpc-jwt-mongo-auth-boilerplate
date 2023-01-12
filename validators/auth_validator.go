package validators

import (
	"fmt"
	"regexp"
)

func SignUpValidator(email string, password string) []error {
	var errors []error

	validEmail := ValidateEmail(email, 3, 30)
	validPassword := ValidatePassword(password, 5, 30)

	if len(validEmail) != 0 {
		errors = append(errors, validEmail...)
	}
	if len(validPassword) != 0 {
		errors = append(errors, validPassword...)
	}

	if len(errors) != 0 {
		return errors
	}

	return nil
}

func ValidateLength(field string, value string, minLength int, maxLength int) error {
	n := len(value)
	if n < minLength || n > maxLength {
		return fmt.Errorf("%v must contain from %d-%d characters", field, minLength, maxLength)
	}
	return nil
}

func ValidateEmail(value string, minLength int, maxLength int) []error {
	// error stack
	var errors []error

	// Length check
	lenErr := ValidateLength("email", value, minLength, maxLength)
	if lenErr != nil {
		errors = append(errors, lenErr)
	}

	// Email format check
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	if !(emailRegex.MatchString(value)) {
		err := fmt.Errorf("email is invalid")
		errors = append(errors, err)
	}

	// Return
	if len(errors) > 0 {
		return errors
	}

	return nil
}

func ValidatePassword(value string, minLength int, maxLength int) []error {
	// error stack
	var errors []error

	// Length check
	lenErr := ValidateLength("passwords", value, minLength, maxLength)
	if lenErr != nil {
		errors = append(errors, lenErr)
	}

	// Return
	if len(errors) > 0 {
		return errors
	}

	return nil
}
