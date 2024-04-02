import { logWithPrefix } from "./logger";

export function isValidateEmail({ email }: { email: string }): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function isValidString({ string, minLength, maxLength, securityLevel = "high", log = false }: {
    string: string,
    minLength: number,
    maxLength?: number,
    securityLevel?: 'high' | 'normal' | 'none',
    log?: boolean
}): boolean {
    if (securityLevel === "high") {
        if (isSecure({ string, xss: true, sqlInjection: true }) === false){
            if (log) logWithPrefix("Possible XSS or SQL Injection detected!");
            return false;
        }
        if (maxLength && string.length > maxLength){
            if (log) logWithPrefix("String length is greater than the maximum length!");
            return false;
        }
        if (string.length < minLength){
            if (log) logWithPrefix("String length is less than the minimum length!");
            return false;
        }
    }
    if (securityLevel === "normal") {
        if (isSecure({ string, xss: true, sqlInjection: false }) === false){
            if (log) logWithPrefix("Possible XSS detected!");
            return false;
        }
        if (maxLength && string.length > maxLength){
            if (log) logWithPrefix("String length is greater than the maximum length!");
            return false;
        }
        if (string.length < minLength){
            if (log) logWithPrefix("String length is less than the minimum length!");
            return false;
        }
    }
    if (securityLevel === "none") {
        if (maxLength && string.length > maxLength){
            if (log) logWithPrefix("String length is greater than the maximum length!");
            return false;
        }
        if (string.length < minLength){
            if (log) logWithPrefix("String length is less than the minimum length!");
            return false;
        }
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