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
        if (isSecure({ string, xss: true, sqlInjection: true, xxeInjection: true, ldapInjection: true, commandInjection: true }) === false){
            if (log) logWithPrefix({message:"Possible XSS, SQL Injection, XXE Injection, LDAP Injection or Command Injection detected!", type:"error"});
            return false;
        }
        if (maxLength && string.length > maxLength){
            if (log) logWithPrefix({message:"String length is greater than the maximum length!", type:"error"});
            return false;
        }
        if (string.length < minLength){
            if (log) logWithPrefix({message:"String length is less than the minimum length!", type:"error"});
            return false;
        }
    }
    if (securityLevel === "normal") {
        if (isSecure({ string, xss: true, sqlInjection: true, xxeInjection: false, ldapInjection: false, commandInjection: false }) === false){
            if (log) logWithPrefix({message:"Possible XSS or SQL Injection detected!", type:"error"});
            return false;
        }
        if (maxLength && string.length > maxLength){
            if (log) logWithPrefix({message:"String length is greater than the maximum length!", type:"error"});
            return false;
        }
        if (string.length < minLength){
            if (log) logWithPrefix({message:"String length is less than the minimum length!", type:"error"});
            return false;
        }
       
    }
    if (securityLevel === "none") {
        if (maxLength && string.length > maxLength){
            if (log) logWithPrefix({message:"String length is greater than the maximum length!", type:"error"});
            return false;
        }
        if (string.length < minLength){
            if (log) logWithPrefix({message:"String length is less than the minimum length!", type:"error"});
            return false;
        }
    }
    if (log) logWithPrefix({message:"String is valid!", type:"success"});
    return true;
}


function isSecure({ string, xss, sqlInjection, xxeInjection, ldapInjection, commandInjection }: {
    string: string,
    xss: boolean,
    sqlInjection: boolean,
    xxeInjection: boolean,
    ldapInjection: boolean,
    commandInjection: boolean
}): boolean {
    if (xss && sqlInjection && xxeInjection && ldapInjection && commandInjection) {
        return isXSS({ string }) && isSQLInjection({ string }) && isXXEInjection({ string }) && isLDAPInjection({ string }) && isCommandInjection({ string });
    }
    if (xss && sqlInjection && xxeInjection && ldapInjection) {
        return isXSS({ string }) && isSQLInjection({ string }) && isXXEInjection({ string }) && isLDAPInjection({ string });
    }
    if (xss && sqlInjection && xxeInjection && commandInjection) {
        return isXSS({ string }) && isSQLInjection({ string }) && isXXEInjection({ string }) && isCommandInjection({ string });
    }
    if (xss && sqlInjection && ldapInjection && commandInjection) {
        return isXSS({ string }) && isSQLInjection({ string }) && isLDAPInjection({ string }) && isCommandInjection({ string });
    }
    if (xss && xxeInjection && ldapInjection && commandInjection) {
        return isXSS({ string }) && isXXEInjection({ string }) && isLDAPInjection({ string }) && isCommandInjection({ string });
    }
    if (sqlInjection && xxeInjection && ldapInjection && commandInjection) {
        return isSQLInjection({ string }) && isXXEInjection({ string }) && isLDAPInjection({ string }) && isCommandInjection({ string });
    }
    if (xss && sqlInjection && xxeInjection) {
        return isXSS({ string }) && isSQLInjection({ string }) && isXXEInjection({ string });
    }
    if (xss && sqlInjection && ldapInjection) {
        return isXSS({ string }) && isSQLInjection({ string }) && isLDAPInjection({ string });
    }
    if (xss && sqlInjection && commandInjection) {
        return isXSS({ string }) && isSQLInjection({ string }) && isCommandInjection({ string });
    }
    if (xss && xxeInjection && ldapInjection) {
        return isXSS({ string }) && isXXEInjection({ string }) && isLDAPInjection({ string });
    }
    if (xss && xxeInjection && commandInjection) {
        return isXSS({ string }) && isXXEInjection({ string }) && isCommandInjection({ string });
    }
    if (xss && ldapInjection && commandInjection) {
        return isXSS({ string }) && isLDAPInjection({ string }) && isCommandInjection({ string });
    }
    if (sqlInjection && xxeInjection && ldapInjection) {
        return isSQLInjection({ string }) && isXXEInjection({ string }) && isLDAPInjection({ string });
    }
    if (sqlInjection && xxeInjection && commandInjection) {
        return isSQLInjection({ string }) && isXXEInjection({ string }) && isCommandInjection({ string });
    }
    if (sqlInjection && ldapInjection && commandInjection) {
        return isSQLInjection({ string }) && isLDAPInjection({ string }) && isCommandInjection({ string });
    }
    if (xxeInjection && ldapInjection && commandInjection) {
        return isXXEInjection({ string }) && isLDAPInjection({ string }) && isCommandInjection({ string });
    }
    if (xss && sqlInjection) {
        return isXSS({ string }) && isSQLInjection({ string });
    }
    if (xss && xxeInjection) {
        return isXSS({ string }) && isXXEInjection({ string });
    }
    if (xss && ldapInjection) {
        return isXSS({ string }) && isLDAPInjection({ string });
    }
    if (xss && commandInjection) {
        return isXSS({ string }) && isCommandInjection({ string });
    }
    if (sqlInjection && xxeInjection) {
        return isSQLInjection({ string }) && isXXEInjection({ string });
    }
    if (sqlInjection && ldapInjection) {
        return isSQLInjection({ string }) && isLDAPInjection({ string });
    }
    if (sqlInjection && commandInjection) {
        return isSQLInjection({ string }) && isCommandInjection({ string });
    }
    if (xxeInjection && ldapInjection) {
        return isXXEInjection({ string }) && isLDAPInjection({ string });
    }
    if (xxeInjection && commandInjection) {
        return isXXEInjection({ string }) && isCommandInjection({ string });
    }
    if (ldapInjection && commandInjection) {
        return isLDAPInjection({ string }) && isCommandInjection({ string });
    }
    if (xss) {
        return isXSS({ string });
    }
    if (sqlInjection) {
        return isSQLInjection({ string });
    }
    if (xxeInjection) {
        return isXXEInjection({ string });
    }
    if (ldapInjection) {
        return isLDAPInjection({ string });
    }
    if (commandInjection) {
        return isCommandInjection({ string });
    }
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

export function isXXEInjection({ string }: { string: string }): boolean {
    // Simple check for entities that may be used in XXE attacks
    const xxeInjectionRegex = /<!ENTITY\s+/i;
    if (xxeInjectionRegex.test(string)) return false;
    return true;
}

export function isLDAPInjection({ string }: { string: string }): boolean {
    // Check for characters often used in LDAP injection attacks
    const ldapInjectionRegex = /(\*|\(|\)|\||&)/g;
    if (ldapInjectionRegex.test(string)) return false;
    return true;
}

export function isCommandInjection({ string }: { string: string }): boolean {
    // Check for patterns that may indicate an attempt to inject system commands
    const commandInjectionRegex = /[`;&|$(<>\)]/g;
    if (commandInjectionRegex.test(string)) return false;
    return true;
}

isValidString({string:"Hello World",minLength:5,securityLevel:"high",log:true});