export function isValidateEmail({ email }: { email: string }): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function isValidString({ string, minLength, maxLength, securityLevel = "high" }: {
    string: string,
    minLength: number,
    maxLength?: number,
    securityLevel?: 'high' | 'normal' | 'none'
}): boolean {
    if (securityLevel === "high") {
        if (isSecure({ string, xss: true, sqlInjection: true }) === false) return false;
        if (maxLength && string.length > maxLength) return false;
        return string.length >= minLength;
    }
    if (securityLevel === "normal") {
        if (isSecure({ string, xss: true, sqlInjection: false }) === false) return false;
        if (maxLength && string.length > maxLength) return false;
        return string.length >= minLength;
    }
    if (securityLevel === "none") {
        if (maxLength && string.length > maxLength) return false;
        return string.length >= minLength;
    }
    return false;
}


export function isSecure({ string, xss = true, sqlInjection = true }: {
    string: string,
    xss?: boolean,
    sqlInjection?: boolean
}): boolean {
    if (xss && sqlInjection) return isXSS({ string }) && isSQLInjection({ string });
    if (xss) return isXSS({ string });
    if (sqlInjection) return isSQLInjection({ string });
    return true;
}


export function isXSS({ string }: { string: string }): boolean {

    // Check for XSS
    const xssRegex = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;
    if (xssRegex.test(string)) return false;
    return true;
}

export function isSQLInjection({ string }: { string: string }): boolean {

    // Check for SQL injections
    const sqlRegex = /(?:\b(?:select|insert|update|delete|alter|drop|create|truncate|exec|union|or|and)\b|\b(?:\d+|null)\b)/gi;
    if (sqlRegex.test(string)) return false;
    return true;
}
